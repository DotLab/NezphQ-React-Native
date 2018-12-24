import React from "react";
import { View, Text, ActivityIndicator, TextInput, TouchableOpacity, Alert } from "react-native";
import { GiftedChat } from 'react-native-gifted-chat';
import * as Nb from 'native-base';

import io from 'socket.io-client';

import { generateSecureRandom } from 'react-native-securerandom';
const forge = require("node-forge");
const nacl = require('tweetnacl');

const encode = forge.util.binary.raw.encode;
const decode = forge.util.binary.raw.decode;
const sha256 = forge.md.sha256.create;

const generateMessageId = () => Math.round(Math.random() * 1000000);

export default class App extends React.Component {
	constructor() {
		super();
		this.state = { messages: [] };
	}

	componentDidMount() {
		this.setState({ loading: "finding entropy" });
		// feed entropy
		generateSecureRandom(4089).then(randomBytes => {
			forge.random.collect(encode(randomBytes));
			nacl.setPRNG((x, n) => {
				const str = forge.random.getBytesSync(n);
				for (var i = 0; i < n; i += 1) {
					x[i] = str.charCodeAt(i);
				}
			});

			// generate rsa
			this.setState({ loading: "generating key" });
			return new Promise((resolve, reject) => {
				setTimeout(() => {
					forge.pki.rsa.generateKeyPair(512, 0x10001, (err, rsa) => {
						if (err) return reject(err);
						resolve(rsa);
					});
				}, 0);
			});
		}).then(rsa => {
			// rsa.privateKey: kA
			// rsa.publicKey: KA
			this.rsa = rsa;
			this.onReconnectButtonPress();
		});
	}

	onReconnectButtonPress() {
		this.setState({ loading: "connecting" });
		this.socket = io("https://q.nezph.com");
		this.socket.on("connect_failed", () => { this.setState({ error: "connect failed", loading: undefined, messages: [] }); })
		this.socket.on("disconnect", () => { this.setState({ error: "broken pipe", loading: undefined, messages: [] }); })
		this.socket.on("error", () => { this.setState({ error: "error", loading: undefined, messages: [] }); })
		
		new Promise(resolve => {
			this.socket.on("connect", resolve);
		}).then(() => {
			// x25519.publicKey: gx1
			// x25519PublicKeySignature: Sign(gx1, kA)
			this.x25519 = nacl.box.keyPair();
			const x25519PublicKey = encode(this.x25519.publicKey);
			const hasher = sha256().update(x25519PublicKey, "raw");
			const x25519PublicKeySignature = this.rsa.privateKey.sign(hasher);
			this.aesIv = forge.random.getBytesSync(32);

			this.setState({ loading: "handshaking", error: undefined });			
			return new Promise(resolve => {
				this.socket.emit("cl_handshake", { 
					rsaPem: forge.pki.publicKeyToPem(this.rsa.publicKey),  // KA 
					x25519PublicKey, x25519PublicKeySignature,
					aesIv: this.aesIv
				}, resolve);
			});
		}).then(roomId => {
			this.roomId = roomId;
			this.setState({ loading: undefined });
			
			const socket = this.socket;
			socket.on("sv_connected", this.onSocketSvConnected.bind(this));
			socket.on("sv_deliver", this.onSocketSvDeliver.bind(this));
		}).catch(err => {
			Alert.alert(err.message);
			throw err;
		});
	}

	onConnectButtonPress() {
		var wishId = Math.round(parseInt(this.wishId));
		if (wishId.toString() === "NaN") return;

		this.setState({ loading: "praying" });
		this.socket.emit("cl_connect_to", wishId, ret => {
			if (ret !== 0) this.setState({ loading: undefined });
		});
	}

	onSocketSvConnected(roomId, cred) {
		// bobRsaPublicKey: KB
		const bobRsaPublicKey = forge.pki.publicKeyFromPem(cred.rsaPem)
		var hash = sha256().update(cred.x25519PublicKey, "raw").digest().bytes();
		var verified = bobRsaPublicKey.verify(hash, cred.x25519PublicKeySignature);
		if (!verified) {
			this.setState({ error: "false prophet" });
			return Promise.reject(1);
		}
		this.bobX25519PublicKey = cred.x25519PublicKey;
		this.bobAesIv = cred.aesIv;

		this.setState(prevState => ({
			loading: undefined,
			messages: GiftedChat.append(prevState.messages, {
				_id: generateMessageId(),
				text: "a secure channel has been established",
				createdAt: new Date(),
				system: true
			}),
		}));
	}

	onSendButtonPress(messages) {
		if (!messages || !messages[0] || !messages[0].text) return;
		const text = messages[0].text;

		new Promise(resolve => {
			setTimeout(() => {
				this.setState({ title: "sending..." });
				
				// calculate keys
				// x25519SharedSecret: gxiyj
				// aesKey: kij = H(gxiyj)
				// hmacKey: H(kij)
				const x25519SharedSecret = nacl.box.before(decode(this.bobX25519PublicKey), this.x25519.secretKey);
				const sharedAesKey = sha256().update(encode(x25519SharedSecret), "raw").digest().bytes();
				const sharedHmacKey = sha256().update(sharedAesKey).digest().bytes();

				// next x25519 pair
				// x25519PublicKey: gxi+1
				const x25519 = nacl.box.keyPair();
				const x25519PublicKey = encode(x25519.publicKey);

				// encryption
				// ciphertext: E(M,kij)
				const cipher = forge.cipher.createCipher("AES-CTR", sharedAesKey);
				cipher.start({ iv: this.aesIv });
				cipher.update(forge.util.createBuffer(text, "utf8"));
				cipher.finish();
				const ciphertext = cipher.output.bytes();
				
				// new aesIv
				const aesIv = forge.random.getBytesSync(32);

				// mac = MAC({gxi+1,E(M,kij)},H(kij))
				const hasher = forge.hmac.create();
				hasher.start("sha256", sharedHmacKey);
				hasher.update(x25519PublicKey);
				hasher.update(ciphertext);
				hasher.update(aesIv);
				const mac = hasher.getMac().bytes();

				this.socket.emit("cl_send", { x25519PublicKey, ciphertext, aesIv, mac }, resolve);

				// update local x25519
				this.x25519 = x25519;
				this.aesIv = aesIv;
			}, 0);
		}).then(() => {
			this.setState(prevState => ({
				title: undefined,
				messages: GiftedChat.append(prevState.messages, messages),
			}));
		});
	}

	processMessage(msg) {
		// calculate keys
		// x25519SharedSecret: gxiyj
		// aesKey: kij = H(gxiyj)
		// hmacKey: H(kij)
		const x25519SharedSecret = nacl.box.before(decode(this.bobX25519PublicKey), this.x25519.secretKey);
		const sharedAesKey = sha256().update(encode(x25519SharedSecret), "raw").digest().bytes();
		const sharedHmacKey = sha256().update(sharedAesKey).digest().bytes();

		const hasher = forge.hmac.create();
		hasher.start("sha256", sharedHmacKey);
		hasher.update(msg.x25519PublicKey);
		hasher.update(msg.ciphertext);
		hasher.update(msg.aesIv);
		const mac = hasher.getMac().bytes();
		if (mac !== msg.mac) return undefined;

		const decipher = forge.cipher.createDecipher("AES-CTR", sharedAesKey);
		decipher.start({ iv: this.bobAesIv });
		decipher.update(forge.util.createBuffer(msg.ciphertext, "raw"));
		const res = decipher.finish();
		if (!res) return undefined;

		this.bobX25519PublicKey = msg.x25519PublicKey;
		this.bobAesIv = msg.aesIv;

		return decipher.output.toString();
	}

	onSocketSvDeliver(msg) {
		text = this.processMessage(msg);
		if (text === undefined) {
			text = "[damaged]";
			this.socket.emit("cl_recheck", {
				
			});
		}

		this.setState(prevState => ({
			messages: GiftedChat.append(prevState.messages, {
				_id: generateMessageId(),
				text,
				createdAt: new Date(),
				user: { _id: 2, name: 'sinner' },
			}),
		}));
	}

	onStopButtonPress() {
		this.socket.disconnect();
		this.setState({ messages: [] });
		this.onReconnectButtonPress();
	}

	render() {
		const state = this.state;
		
		if (state.loading) {
			return <View style={{ alignContent: "stretch", justifyContent: "center", height: "100%", backgroundColor: "#000" }}>
				<Text style={{ fontSize: 25, alignSelf: "center", color: "#aaa", paddingBottom: 10 }}>{state.loading}</Text>
				<ActivityIndicator size="large" color="#777" />
			</View>;
		}

		if (state.error) {
			return <View style={{ alignContent: "stretch", justifyContent: "center", height: "100%", backgroundColor: "#000" }}>
				<Text style={{ fontSize: 25, alignSelf: "center", color: "#aaa", paddingBottom: 10 }}>{state.error}</Text>
				<TouchableOpacity style={{ alignSelf: "center", padding: 5, width: 120, borderWidth: 1, borderColor: "#aaa", borderRadius: 5 }} onPress={this.onReconnectButtonPress.bind(this)}>
					<Text style={{ alignSelf: "center", color: "#aaa", fontSize: 25 }}>repent</Text>
				</TouchableOpacity>
			</View>;
		}

		if (state.messages.length > 0) {
			return <Nb.Container style={{ flex: 1 }}>
				<Nb.Header>
					<Nb.Left>
						<Nb.Button transparent onPress={this.onStopButtonPress.bind(this)}>
							<Nb.Icon type="AntDesign" name="close" />
						</Nb.Button>
					</Nb.Left>
					<Nb.Body>
						<Nb.Title>{state.title || "sinner"}</Nb.Title>
					</Nb.Body>
					<Nb.Right />
				</Nb.Header>
				<View style={{ flex: 1 }}>
					<GiftedChat
						messages={state.messages} 
						onSend={this.onSendButtonPress.bind(this)} 
						user={{ _id: 1 }}
					/>
				</View>
			</Nb.Container>
		}

		return <View style={{ alignContent: "stretch", justifyContent: "center", height: "100%", backgroundColor: "#000" }}>
			<Text style={{ fontSize: 25, alignSelf: "center", color: "#aaa", paddingBottom: 10 }}>i am {this.roomId}</Text>
			<View style={{ flexDirection: "row", justifyContent: "center", paddingBottom: 10 }}>
				<Text style={{color: "#aaa", padding: 5, fontSize: 25}}>i want </Text>
				<TextInput style={{ padding: 5, fontSize: 25, width: 100, color: "#aaa", borderWidth: 1, borderColor: "#aaa", borderRadius: 5 }} keyboardType="decimal-pad" onChangeText={text => this.wishId = text} />
			</View>
			<TouchableOpacity style={{ alignSelf: "center", padding: 5, width: 120, borderWidth: 1, borderColor: "#aaa", borderRadius: 5 }} onPress={this.onConnectButtonPress.bind(this)}>
				<Text style={{ alignSelf: "center", color: "#aaa", fontSize: 25 }}>pray</Text>
			</TouchableOpacity>
		</View>;
	}
}