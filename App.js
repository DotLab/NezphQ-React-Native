import React from "react";
import { View, Text, ActivityIndicator, TextInput, TouchableOpacity, Alert } from "react-native";
import { GiftedChat } from 'react-native-gifted-chat';
import * as Nb from 'native-base';

import io from 'socket.io-client';

import { generateSecureRandom } from 'react-native-securerandom';
const forge = require("node-forge");
const nacl = require('tweetnacl');

export default class App extends React.Component {
	constructor() {
		super();
		this.state = { loading: "generating key" };
	}

	componentDidMount() {
		generateSecureRandom(2048).then(randomBytes => {
			forge.random.collect(forge.util.binary.raw.encode(randomBytes));
			nacl.setPRNG((x, n) => {
				const str = forge.random.getBytesSync(n);
				for (var i = 0; i < n; i += 1) {
					x[i] = str.charCodeAt(i);
				}
			});

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
		this.socket = io("http://localhost:6021");
		this.socket.on("disconnect", () => {
			this.setState({ error: "broken pipe" });
		})
		new Promise(resolve => {
			this.socket.on("connect", resolve);
		}).then(() => {
			// x25519.publicKey: gx1
			// x25519PublicKeySignature: Sign(gx1, kA)
			this.x25519 = nacl.box.keyPair();
			this.x25519PublicKeyBase64 = forge.util.binary.base64.encode(this.x25519.publicKey);
				// forge.util.encode64(new forge.util.ByteStringBuffer(this.x25519.publicKey).bytes());
				// naclUtil.encodeBase64(this.x25519.publicKey);
			const hasher = forge.md.sha256.create().update(this.x25519PublicKeyBase64, "utf8");
			this.x25519PublicKeySignature = this.rsa.privateKey.sign(hasher);

			this.aesIv = forge.random.getBytesSync(32);

			this.setState({ loading: "handshaking", error: null });
			return new Promise(resolve => {
				this.socket.emit("cl_handshake", { 
					rsaPem: forge.pki.publicKeyToPem(this.rsa.publicKey),  // KA 
					x25519PublicKeyBase64: this.x25519PublicKeyBase64,  // gx1
					x25519PublicKeySignature: this.x25519PublicKeySignature,  // Sign(gx1, kA),
					aesIv: this.aesIv
				}, resolve);
			});
		}).then(roomId => {
			this.roomId = roomId;
			this.setState({ loading: null });
			
			const socket = this.socket;
			socket.on("sv_connected", (roomId, cred) => {
				this.bobId = roomId;
				this.bobCred = cred;
				
				// bobRsaPublicKey: KB
				this.bobRsaPublicKey = forge.pki.publicKeyFromPem(cred.rsaPem)
				var hash = forge.md.sha256.create().update(cred.x25519PublicKeyBase64, "utf8").digest().bytes();
				var verified = this.bobRsaPublicKey.verify(hash, cred.x25519PublicKeySignature);
				if (!verified) {
					this.setState({ error: "false prophet" });
					return Promise.reject(1);
				}

				// x25519SharedSecret: gx1y1
				// aesKey: k11 = H(gx1y1)
				this.x25519SharedSecret = nacl.box.before(
					forge.util.binary.base64.decode(cred.x25519PublicKeyBase64),
					// forge.util.decode64(new forge.util.ByteStringBuffer(cred.x25519PublicKeyBase64).bytes()),
					this.x25519.secretKey);
					// naclUtil.decodeBase64(cred.x25519PublicKeyBase64), this.x25519.secretKey);
				this.aesKey = forge.md.sha256.create().update(
					forge.util.binary.base64.encode(this.x25519SharedSecret),
					// forge.util.encode64(new forge.util.ByteStringBuffer(this.x25519SharedSecret).bytes()), 
					"utf8").digest().bytes();
					// naclUtil.encodeBase64(this.x25519SharedSecret), "utf8").digest().bytes();
				this.hmacKey = forge.md.sha256.create().update(this.aesKey).digest().bytes();

				const cipher = forge.cipher.createCipher("AES-CTR", this.aesKey);
				cipher.start({ iv: this.aesIv });
				cipher.update(forge.util.createBuffer("test", "utf8"));
				cipher.finish();
				var encrypted = cipher.output;
				
				const decipher = forge.cipher.createDecipher("AES-CTR", this.aesKey);
				decipher.start({ iv: cred.aesIv });
				decipher.update(encrypted);
				const res = decipher.finish();
				Alert.alert(decipher.output.toString());
				
				const hmac = forge.hmac.create();
				hmac.start("sha256", this.hmacKey);
				hmac.update("123");

				this.setState({ messages: [ {
					_id: 1,
					text: "a secure channel has been established",
					createdAt: new Date(),
					system: true
				} ] });
			});

			socket.on("sv_deliver", msg => {
				Alert.alert(msg);
			});
		}).catch(err => {
			if (err !== 1) throw err;
		});
	}

	onConnectButtonPress() {
		var wishId = Math.round(parseInt(this.wishId));
		if (wishId.toString() === "NaN") return;
		this.socket.emit("cl_connect_to", wishId, ret => {
			if (ret === 0) {

			}
		});
	}

	onSend(messages) {
		console.log(messages);
		this.setState(prevState => ({
			messages: GiftedChat.append(prevState.messages, messages),
		}));
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

		if (state.messages) {
			return <Nb.Container style={{ flex: 1 }}>
				<Nb.Header>
					<Nb.Left>
						<Nb.Button transparent>
							<Nb.Icon type="AntDesign" name="close" />
						</Nb.Button>
					</Nb.Left>
					<Nb.Body>
						<Nb.Title>sinner</Nb.Title>
					</Nb.Body>
					<Nb.Right />
				</Nb.Header>
				<View style={{ flex: 1 }}>
					<GiftedChat
						messages={state.messages} 
						onSend={this.onSend.bind(this)} 
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