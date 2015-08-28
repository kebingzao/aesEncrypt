// aes 加解密方法集
window.aesUtil = {
	// aes 加密的iv，这个是加密向量，为16位，跟解密端要约定的值，一般不变
	_aes_iv : "0102030405060708",
	// 初始化aes helper
	// password --> aes 的解密key
	// encrypt --> 是加密还是解密
	helper: function(password, encrypt) {
		var cipher = new System.Security.Cryptography.RijndaelManaged();
		var key = System.Text.Encoding.ASCII.GetBytes(password);
		var iv = System.Text.Encoding.ASCII.GetBytes(this._aes_iv);
		var cryptor = null;
		if (encrypt) {
			cryptor = cipher.CreateEncryptor(key, iv);
		} else {
			cryptor = cipher.CreateDecryptor(key, iv);
		}
		return cryptor;
	},
	// aes 加解密的计算过程
	cipherStreamWrite:function(cryptor, input){
		var inputBuffer = new System.Byte(input.length);
		// Copy data bytes to input buffer.
		System.Buffer.BlockCopy(input, 0, inputBuffer, 0, inputBuffer.length);
		// Create a MemoryStream to hold the output bytes.
		var stream = new System.IO.MemoryStream();
		// Create a CryptoStream through which we are going to be processing our data.
		var mode = System.Security.Cryptography.CryptoStreamMode.Write;
		var cryptoStream = new System.Security.Cryptography.CryptoStream(stream, cryptor, mode);
		// Start the crypting process.
		cryptoStream.Write(inputBuffer, 0, inputBuffer.length);
		// Finish crypting.
		cryptoStream.FlushFinalBlock();
		// Convert data from a memoryStream into a byte array.
		var outputBuffer = stream.ToArray();
		// Close both streams.
		stream.Close();
		cryptoStream.Close();
		return outputBuffer;
	},
	// 生成16位随机AES密钥
	createAESKey: function(){
		return hex_md5("hehe@#$%^" + new Date().getTime()).substr(0,16);
	},
	// aes 加密并用base64 输出
	encryptToBase64: function(password, s) {
		// Turn input strings into a byte array.
		var bytes = System.Text.Encoding.UTF8.GetBytes(s);
		// Get encrypted bytes.
		var encryptedBytes = this.encrypt(password, bytes);
		// Convert encrypted data into a base64-encoded string.
		var base64String = System.Convert.ToBase64String(encryptedBytes);
		// Return encrypted string.
		return base64String;
	},
	// aes 加密
	encrypt: function(password, bytes) {
		// Create an instance of the Rihndael class.
		// Create a encryptor.
		var encryptor = this.helper(password, true);
		// Return encrypted bytes.
		return this.cipherStreamWrite(encryptor, bytes);
	},
	// aes 解密并用base64输出
	decryptFromBase64: function(password, base64String) {
		// Convert Base64 string into a byte array.
		var encryptedBytes = System.Convert.FromBase64String(base64String);
		var bytes = this.decrypt(password, encryptedBytes);
		// Convert decrypted data into a string.
		var s = System.Text.Encoding.UTF8.GetString(bytes);
		// Return decrypted string.
		return s;
	},
	// aes 解密
	decrypt: function(password, bytes) {
		// Create an instance of the Rihndael class.
		// Create a encryptor.
		var decryptor = this.helper(password, false);
		// Return encrypted bytes.
		return this.cipherStreamWrite(decryptor, bytes);
	}
};