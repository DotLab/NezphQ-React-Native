import React from "react";
import { View, Text, ActivityIndicator, TextInput, TouchableOpacity, Alert } from "react-native";
import io from 'socket.io-client';

const forge = require("node-forge");
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');

export default class App extends React.Component {
	constructor() {
		super();
		this.state = { loading: "generating key" };
	}

	componentDidMount() {
		new Promise((resolve, reject) => {
			setTimeout(() => {
				forge.pki.rsa.generateKeyPair(512, 0x10001, (err, rsa) => {
					if (err) return reject(err);
					resolve(rsa);
				});
			}, 0);
		}).then(rsa => {
			// rsa.privateKey: kA
			// rsa.publicKey: KA
			this.rsa = rsa;
			this.onReconnectButtonPress();
		});
	}

	onReconnectButtonPress() {
		this.setState({ loading: "connecting" });
		this.socket = io("http://10.0.2.2:3000");
		this.socket.on("disconnect", () => {
			this.setState({ error: "broken pipe" });
		})
		new Promise(resolve => {
			this.socket.on("connect", resolve);
		}).then(() => {
			// x25519.publicKey: gx1
			// x25519PublicKeySignature: Sign(gx1, kA)
			this.x25519 = nacl.box.keyPair();
			this.x25519PublicKeyBase64 = naclUtil.encodeBase64(this.x25519.publicKey);
			const hasher = forge.md.sha256.create();
			hasher.update(this.x25519PublicKeyBase64, "utf8");
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
				var hasher = forge.md.sha256.create();
				hasher.update(cred.x25519PublicKeyBase64, "utf8");
				var verified = this.bobRsaPublicKey.verify(hasher.digest().bytes(), cred.x25519PublicKeySignature);
				if (!verified) {
					this.setState({ error: "false prophet" });
					return Promise.reject(1);
				}

				// x25519SharedSecret: gx1y1
				// aesKey: k11 = H(gx1y1)
				this.x25519SharedSecret = nacl.box.before(naclUtil.decodeBase64(cred.x25519PublicKeyBase64), this.x25519.secretKey);
				var hasher = forge.md.sha256.create();
				hasher.update(naclUtil.encodeBase64(this.x25519SharedSecret), "utf8");
				this.aesKey = hasher.digest().bytes();

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
		// if (state.roomId) {
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
		// }
	}
}