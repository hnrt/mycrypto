package com.hideakin.mycrypto;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.hideakin.mycrypto.constant.Algorithm;
import com.hideakin.mycrypto.constant.CipherMode;
import com.hideakin.mycrypto.constant.Padding;
import com.hideakin.util.CommandLineParameters;
import com.hideakin.util.HexString;
import com.hideakin.util.TextHelpers;

public class MyCryptographyUtilityApplication {

	public static final String VERSION = "0.8.0";

	public static final String DESCRIPTION = "My Cryptography Utility version %s\n";

	private static final int AES_256_KEY_LENGTH = 256 / 8;
	private static final int AES_192_KEY_LENGTH = 192 / 8;
	private static final int AES_128_KEY_LENGTH = 128 / 8;
	private static final int AES_IV_LENGTH = 16;
	private static final int AES_GCM_NONCE_LENGTH = 12;
	private static final int AES_GCM_TAG_LENGTH_DEFAULT = 16;
	private static final int AES_GCM_TAG_LENGTH_MIN = 12;
	private static final int AES_GCM_TAG_LENGTH_MAX = 16;
	
	private static final int FLAG_OVERWRITE = 1 << 0;
	private static final int FLAG_IN_TO_CLOSE = 1 << 1;
	private static final int FLAG_OUT_TO_CLOSE = 1 << 2;

	private static final int DIGEST_MODE = 999;

	private Algorithm _algorithm = Algorithm.UNDEFINED;
	private CipherMode _cipherMode = CipherMode.UNDEFINED;
	private Padding _padding = Padding.UNDEFINED;
	private int _keyLength = 0;
	private int _ivLength = 0;
	private int _nonceLength = 0;
	private int _tagLength = 0;
	private String _passphrase;
	private byte[] _key;
	private byte[] _iv;
	private byte[] _nonce;
	private byte[] _aad; // Additional Authenticated Data
	private byte[] _tag;
	private String _inFileName;
	private String _outFileName;
	private Path _outPath;
	private Path _tmpPath;
	private int _operationMode = 0; // Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE or DIGEST_MODE
	private int _flags = 0;
	private PrintStream _info;
	private long inBytes = 0L;
	private long outBytes = 0L;
	
	private final Map<CipherMode, Supplier<Cipher>> _cipherSupplier = new HashMap<CipherMode, Supplier<Cipher>>() {
		{
			put(CipherMode.CBC, () -> { return getCipherWithKeyAndIv(); });
			put(CipherMode.ECB, () -> { return getCipherWithKey(); });
			put(CipherMode.CFB, () -> { return getCipherWithKeyAndIv(); });
			put(CipherMode.CFB8, () -> { return getCipherWithKeyAndIv(); });
			put(CipherMode.OFB, () -> { return getCipherWithKeyAndIv(); });
			put(CipherMode.OFB8, () -> { return getCipherWithKeyAndIv(); });
			put(CipherMode.CTR, () -> { return getCipherWithKeyAndIv(); });
			put(CipherMode.GCM, () -> { return getCipherWithGcmParameterSpec(); });
		}
	};

	public MyCryptographyUtilityApplication() {
	}

	private void setTransformation(Algorithm algorithm, CipherMode mode, Padding padding, int keyLength) {
		if (_algorithm != Algorithm.UNDEFINED) {
			if (_algorithm == Algorithm.AES) {
				throw new RuntimeException("Cipher is specified more than once.");
			} else {
				throw new RuntimeException("Both cipher and digest are specified at the same time. Specify one of them at a time.");
			}
		}
		_algorithm = algorithm;
		_cipherMode = mode;
		_padding = padding;
		_keyLength = keyLength;
		if (mode.useIV()) {
			_ivLength = AES_IV_LENGTH;
		} else if (mode == CipherMode.GCM) {
			_nonceLength = AES_GCM_NONCE_LENGTH;
		}
	}

	private boolean hasTagLength() {
		return _tagLength != 0; 
	}

	private void setTagLength(int value) {
		if (AES_GCM_TAG_LENGTH_MIN <= value && value <= AES_GCM_TAG_LENGTH_MAX) {
			_tagLength = value;
		} else {
			throw new RuntimeException("Tag length is out of range.");
		}
	}

	private boolean hasPassphrase() {
		return _passphrase != null;
	}

	private boolean hasKey() {
		return _key != null;
	}

	private boolean hasIv() {
		return _iv != null;
	}

	private boolean hasNonce() {
		return _nonce != null;
	}

	private void setPassphrase(String value) {
		_passphrase = value;
	}

	private void setKey(byte[] value) {
		_key = value;
	}

	private void setIv(byte[] value) {
		_iv = value;
	}

	private void setNonce(byte[] value) {
		_nonce = value;
	}

	private boolean hasAAD() {
		return _aad != null;
	}

	private void setAad(byte[] value) {
		_aad = value;
	}

	private void setOperation(int operation) {
		_operationMode = operation;
	}

	private void setInputPath(String fileName) {
		_inFileName = fileName;
	}

	private void setOutputPath(String fileName) {
		_outFileName = fileName;
	}
	
	private void setFlags(int value) {
		_flags |= value;
	}
	
	private void resetFlags(int value) {
		_flags &= ~value;
	}

	private boolean checkFlags(int value) {
		return (_flags & value) == value;
	}

	private void setDigestMode(Algorithm algorithm) {
		if (_algorithm != Algorithm.UNDEFINED) {
			if (_algorithm == Algorithm.AES) {
				throw new RuntimeException("Both cipher and digest are specified at the same time. Specify one of them at a time.");
			} else {
				throw new RuntimeException("Digest is specified more than once.");
			}
		}
		_operationMode = DIGEST_MODE;
		_algorithm = algorithm;
	}

	public void run() throws Exception {
		switch (_operationMode) {
		case Cipher.ENCRYPT_MODE:
			runInEncryptMode();
			break;
		case Cipher.DECRYPT_MODE:
			runInDecryptMode();
			break;
		case DIGEST_MODE:
			runInDigestMode();
			break;
		default:
			throw new RuntimeException("Neither cipher nor digest is specified. Specify one of them at least.");
		}
	}

	public void runInEncryptMode() throws Exception {
		verifyParameters(true);
		InputStream in = null;
		OutputStream out = null;
		try {
			in = openInput();
			out = openOutput();
			byte[] buf = new byte[8192];
			int n;
			if (_nonce != null) {
				out.write(_nonce);
				outBytes += _nonce.length;
			} else if (_iv != null) {
				out.write(_iv);
				outBytes += _iv.length;
			}
			Cipher cipher = getCipher();
			while ((n = in.read(buf)) >= 0) {
				if (n > 0) {
					inBytes += n;
					byte[] result = cipher.update(buf, 0, n);
					if (result != null) {
						out.write(result);
						outBytes += result.length;
					}
				}
			}
			closeInput(in);
			byte[] result = cipher.doFinal();
			if (result != null) {
				out.write(result);
				outBytes += result.length;
				if (_tag != null) {
					storeLastBytes(result, result.length, _tag);
					_info.printf("%10s %s\n", "TAG", HexString.toString(_tag));
				}
			}
			out.flush();
			_info.printf("%16s in\n", TextHelpers.numberOfBytes(inBytes));
			_info.printf("%16s out\n", TextHelpers.numberOfBytes(outBytes));
			commitOutput(out);
		} finally {
			closeInput(in);
			closeOutput(out);
		}
	}

	public void runInDecryptMode() throws Exception {
		verifyParameters(false);
		InputStream in = null;
		OutputStream out = null;
		try {
			in = openInput();
			out = openOutput();
			byte[] buf = new byte[8192];
			int n;
			if (_cipherMode.useNonce()) {
				if (_nonce == null) {
					_nonce = new byte[_nonceLength];
					n = in.read(_nonce);
					if (n != _nonceLength) {
						throw new RuntimeException("Failed to read nonce.");
					}
					inBytes += n;
				}
			} else if (_cipherMode.useIV()) {
				if (_iv == null) {
					_iv = new byte[_ivLength];
					n = in.read(_iv);
					if (n != _ivLength) {
						throw new RuntimeException("Failed to read IV.");
					}
					inBytes += n;
				}
			}
			Cipher cipher = getCipher();
			while ((n = in.read(buf)) >= 0) {
				if (n > 0) {
					inBytes += n;
					if (_tag != null) {
						storeLastBytes(buf, n, _tag);
					}
					byte[] result = cipher.update(buf, 0, n);
					if (result != null) {
						out.write(result);
						outBytes += result.length;
					}
				}
			}
			closeInput(in);
			byte[] result = cipher.doFinal();
			if (result != null) {
				out.write(result);
				outBytes += result.length;
				if (_tag != null) {
					_info.printf("%10s %s\n", "TAG", HexString.toString(_tag));
				}
			}
			out.flush();
			_info.printf("%16s in\n", TextHelpers.numberOfBytes(inBytes));
			_info.printf("%16s out\n", TextHelpers.numberOfBytes(outBytes));
			commitOutput(out);
		} finally {
			closeInput(in);
			closeOutput(out);
		}
	}

	private void verifyParameters(boolean generateIfNotSpecified) throws Exception {
		verifyCommon();
		verifyKey();
		verifyIV(generateIfNotSpecified);
		verifyNonce(generateIfNotSpecified);
	}

	private void verifyCommon() throws Exception {
		if (_algorithm == Algorithm.UNDEFINED) {
			throw new RuntimeException("Cipher is not specified.");
		}
		if (_inFileName == null) {
			throw new RuntimeException("Input file path is not specified.");
		}
		if (_outFileName == null) {
			throw new RuntimeException("Output file path is not specified.");
		}
	}

	private void verifyKey() throws Exception {
		if (!hasKey() && !hasPassphrase()) {
			throw new RuntimeException("Neither key nor passphrase is specified. Specify one or the other.");
		} else if (hasKey() && hasPassphrase()) {
			throw new RuntimeException("Both key and passphrase are specified at the same time. Specify one or the other.");
		} else if (hasPassphrase()) {
			_key = adjustLength(generate32Bytes(_passphrase), _keyLength);
		} else if (_key.length != _keyLength) {
			throw new RuntimeException(String.format("Key is not valid in length. Expected=%d Actual=%d", _keyLength, _key.length));
		}
	}

	private void verifyIV(boolean generateIfNotSpecified) throws Exception {
		if (_ivLength > 0) {
			if (hasIv()) {
				if (_ivLength != _iv.length) {
					throw new RuntimeException(String.format("IV is not valid in length. Expected=%d Actual=%d", _ivLength, _iv.length));
				}
			} else if (generateIfNotSpecified) {
				_iv = adjustLength(generate32Bytes(null), _ivLength);
			}
		} else if (hasIv()) {
			throw new RuntimeException("Initial vector cannot be specified for the target cipher.");
		}
	}

	private void verifyNonce(boolean generateIfNotSpecified) throws Exception {
		if (_nonceLength > 0) {
			if (hasNonce()) {
				if (_nonceLength != _nonce.length) {
					throw new RuntimeException(String.format("Nonce is not valid in length. Expected=%d Actual=%d", _nonceLength, _nonce.length));
				}
			} else if (generateIfNotSpecified) {
				_nonce = adjustLength(generate32Bytes(null), _nonceLength);
			}
			
		} else if (hasNonce()) {
			throw new RuntimeException("Nonce cannot be specified for the target cipher.");
		} else if (hasAAD()) {
			throw new RuntimeException("Additional authenticated data cannot be specified for the target cipher.");
		} else if (hasTagLength()) {
			throw new RuntimeException("Tag length cannot be specified for the target cipher.");
		}
	}

	private static byte[] adjustLength(byte[] value, int length) {
		if (value.length != length) {
			return Arrays.copyOf(value, length);
		} else {
			return value;
		}
	}

	private InputStream openInput() throws Exception {
		InputStream in;
		if ("-".equals(_inFileName)) {
			in = System.in;
		} else {
			Path path = Paths.get(_inFileName);
			if (!Files.exists(path)) {
				throw new RuntimeException("Input file is not found.");
			}
			in = Files.newInputStream(path);
			setFlags(FLAG_IN_TO_CLOSE);
		}
		return in;
	}
	
	private void closeInput(InputStream in) {
		if (checkFlags(FLAG_IN_TO_CLOSE)) {
			try {
				in.close();
				resetFlags(FLAG_IN_TO_CLOSE);
			} catch (Exception e) {
				printError(e);
			}
		}
	}

	private OutputStream openOutput() throws Exception {
		OutputStream out;
		if ("-".equals(_outFileName)) {
			out = System.out;
			_info = System.err;
		} else {
			_outPath = Paths.get(_outFileName);
			if (!checkFlags(FLAG_OVERWRITE) && Files.exists(_outPath)) {
				throw new RuntimeException("Output file already exists.");
			}
			_tmpPath = Paths.get(String.format("%s.%d", _outFileName, System.currentTimeMillis()));
			out = Files.newOutputStream(_tmpPath);
			setFlags(FLAG_OUT_TO_CLOSE);
			_info = System.out;
		}
		return out;
	}
	
	private void commitOutput(OutputStream out) throws Exception {
		if (checkFlags(FLAG_OUT_TO_CLOSE)) {
			out.close();
			resetFlags(FLAG_OUT_TO_CLOSE);
			if (checkFlags(FLAG_OVERWRITE)) {
				Files.move(_tmpPath, _outPath, StandardCopyOption.REPLACE_EXISTING);
			} else if (Files.exists(_outPath)) {
				throw new RuntimeException("Output file already exists.");
			} else {
				Files.move(_tmpPath, _outPath);
			}
		}
	}

	private void closeOutput(OutputStream out) {
		if (checkFlags(FLAG_OUT_TO_CLOSE)) {
			try {
				out.close();
				resetFlags(FLAG_OUT_TO_CLOSE);
			} catch (Exception e) {
				printError(e);
			}
		}
	}

	private static void storeLastBytes(byte[] src, int n, byte[] dst) {
		if (n >= dst.length) {
			System.arraycopy(src, n - dst.length, dst, 0, dst.length);
		} else {
			int m = dst.length - n;
			byte[] prv = Arrays.copyOfRange(dst, n, m);
			System.arraycopy(prv, 0, dst, 0, m);
			System.arraycopy(src, 0, dst, m, n);
		}
	}

	private Cipher getCipher() throws Exception {
		return _cipherSupplier.get(_cipherMode).get();
	}

	private Cipher getCipherWithKeyAndIv() {
		try {
			SecretKeySpec keySpec = new SecretKeySpec(_key, _algorithm.label());
			IvParameterSpec ivSpec = new IvParameterSpec(_iv);
			Cipher cipher = Cipher.getInstance(transformation());
			cipher.init(_operationMode, keySpec, ivSpec);
			_info.printf("%10s %s\n", "KEY", HexString.toString(_key));
			_info.printf("%10s %s\n", "IV", HexString.toString(_iv));
			return cipher;
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	private Cipher getCipherWithKey() {
		try {
			SecretKeySpec keySpec = new SecretKeySpec(_key, _algorithm.label());
			Cipher cipher = Cipher.getInstance(transformation());
			cipher.init(_operationMode, keySpec);
			_info.printf("%10s %s\n", "KEY", HexString.toString(_key));
			return cipher;
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	private Cipher getCipherWithGcmParameterSpec() {
		try {
			if (_tagLength == 0) {
				_tagLength = AES_GCM_TAG_LENGTH_DEFAULT;
			}
			SecretKeySpec keySpec = new SecretKeySpec(_key, _algorithm.label());
			GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(_tagLength * 8, _nonce);
			Cipher cipher = Cipher.getInstance(transformation());
			cipher.init(_operationMode, keySpec, gcmParameterSpec);
			_info.printf("%10s %s\n", "KEY", HexString.toString(_key));
			_info.printf("%10s %s\n", "NONCE", HexString.toString(_nonce));
			if (_aad != null) {
				cipher.updateAAD(_aad);
				_info.printf("%10s %s\n", "AAD", HexString.toString(_aad));
			}
			_tag = new byte[_tagLength];
			return cipher;
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	private String transformation() {
		return String.format("%s/%s/%s", _algorithm.label(), _cipherMode.label(), _padding.label());
	}

	private static byte[] generate32Bytes(String value) {
		try {
			if (value == null) {
				value = String.format("%d", System.nanoTime());
			}
			MessageDigest md = MessageDigest.getInstance(Algorithm.SHA256.label());
			return md.digest(value.getBytes());
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	public void runInDigestMode() throws Exception {
		if (hasKey()) {
			throw new RuntimeException("Key cannot be specified for digest.");
		}
		if (hasPassphrase()) {
			throw new RuntimeException("Passphrase cannot be specified for digest.");
		}
		if (hasIv()) {
			throw new RuntimeException("IV cannot be specified for digest.");
		}
		if (hasNonce()) {
			throw new RuntimeException("Nonce cannot be specified for digest.");
		}
		if (hasAAD()) {
			throw new RuntimeException("AAD cannot be specified for digest.");
		}
		if (hasTagLength()) {
			throw new RuntimeException("Tag length cannot be specified for digest.");
		}
		if (_inFileName == null) {
			throw new RuntimeException("Input file path is not specified.");
		}
		if (_outFileName == null) {
			_outFileName = "-";
		}
		InputStream in = null;
		OutputStream out = null;
		try {
			in = openInput();
			out = openOutput();
			byte[] buffer = new byte[8192];
			int n;
			MessageDigest md = MessageDigest.getInstance(_algorithm.label());
			while ((n = in.read(buffer)) >= 0) {
				md.update(buffer, 0, n);
			}
			byte[] result = md.digest();
			out.write(String.format("%s%s", HexString.toString(result).toLowerCase(), System.lineSeparator()).getBytes());
			out.flush();
			commitOutput(out);
		} finally {
			closeInput(in);
			closeOutput(out);
		}
	}

	public CommandLineParameters commandLineParameters() {
		return (new CommandLineParameters())
				.add("aes-128-ecb", transformationDescription(Algorithm.AES, CipherMode.ECB, Padding.PKCS5, 128), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.ECB, Padding.PKCS5, AES_128_KEY_LENGTH);
					return true;
				})
				.add("aes-192-ecb", transformationDescription(Algorithm.AES, CipherMode.ECB, Padding.PKCS5, 192), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.ECB, Padding.PKCS5, AES_192_KEY_LENGTH);
					return true;
				})
				.add("aes-256-ecb", transformationDescription(Algorithm.AES, CipherMode.ECB, Padding.PKCS5, 256), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.ECB, Padding.PKCS5, AES_256_KEY_LENGTH);
					return true;
				})
				.add("aes-128-cbc", transformationDescription(Algorithm.AES, CipherMode.CBC, Padding.PKCS5, 128), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.CBC, Padding.PKCS5, AES_128_KEY_LENGTH);
					return true;
				})
				.add("aes-192-cbc", transformationDescription(Algorithm.AES, CipherMode.CBC, Padding.PKCS5, 192), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.CBC, Padding.PKCS5, AES_192_KEY_LENGTH);
					return true;
				})
				.add("aes-256-cbc", transformationDescription(Algorithm.AES, CipherMode.CBC, Padding.PKCS5, 256), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.CBC, Padding.PKCS5, AES_256_KEY_LENGTH);
					return true;
				})
				.add("aes-128-cfb", transformationDescription(Algorithm.AES, CipherMode.CFB, Padding.NONE, 128), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.CFB, Padding.NONE, AES_128_KEY_LENGTH);
					return true;
				})
				.add("aes-192-cfb", transformationDescription(Algorithm.AES, CipherMode.CFB, Padding.NONE, 192), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.CFB, Padding.NONE, AES_192_KEY_LENGTH);
					return true;
				})
				.add("aes-256-cfb", transformationDescription(Algorithm.AES, CipherMode.CFB, Padding.NONE, 256), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.CFB, Padding.NONE, AES_256_KEY_LENGTH);
					return true;
				})
				.add("aes-128-cfb8", transformationDescription(Algorithm.AES, CipherMode.CFB8, Padding.NONE, 128), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.CFB8, Padding.NONE, AES_128_KEY_LENGTH);
					return true;
				})
				.add("aes-192-cfb8", transformationDescription(Algorithm.AES, CipherMode.CFB8, Padding.NONE, 192), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.CFB8, Padding.NONE, AES_192_KEY_LENGTH);
					return true;
				})
				.add("aes-256-cfb8", transformationDescription(Algorithm.AES, CipherMode.CFB8, Padding.NONE, 256), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.CFB8, Padding.NONE, AES_256_KEY_LENGTH);
					return true;
				})
				.add("aes-128-ofb", transformationDescription(Algorithm.AES, CipherMode.OFB, Padding.NONE, 128), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.OFB, Padding.NONE, AES_128_KEY_LENGTH);
					return true;
				})
				.add("aes-192-ofb", transformationDescription(Algorithm.AES, CipherMode.OFB, Padding.NONE, 192), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.OFB, Padding.NONE, AES_192_KEY_LENGTH);
					return true;
				})
				.add("aes-256-ofb", transformationDescription(Algorithm.AES, CipherMode.OFB, Padding.NONE, 256), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.OFB, Padding.NONE, AES_256_KEY_LENGTH);
					return true;
				})
				.add("aes-128-ofb8", transformationDescription(Algorithm.AES, CipherMode.OFB8, Padding.NONE, 128), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.OFB8, Padding.NONE, AES_128_KEY_LENGTH);
					return true;
				})
				.add("aes-192-ofb8", transformationDescription(Algorithm.AES, CipherMode.OFB8, Padding.NONE, 192), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.OFB8, Padding.NONE, AES_192_KEY_LENGTH);
					return true;
				})
				.add("aes-256-ofb8", transformationDescription(Algorithm.AES, CipherMode.OFB8, Padding.NONE, 256), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.OFB8, Padding.NONE, AES_256_KEY_LENGTH);
					return true;
				})
				.add("aes-128-ctr", transformationDescription(Algorithm.AES, CipherMode.CTR, Padding.NONE, 128), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.CTR, Padding.NONE, AES_128_KEY_LENGTH);
					return true;
				})
				.add("aes-192-ctr", transformationDescription(Algorithm.AES, CipherMode.CTR, Padding.NONE, 192), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.CTR, Padding.NONE, AES_192_KEY_LENGTH);
					return true;
				})
				.add("aes-256-ctr", transformationDescription(Algorithm.AES, CipherMode.CTR, Padding.NONE, 256), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.CTR, Padding.NONE, AES_256_KEY_LENGTH);
					return true;
				})
				.add("aes-128-gcm", transformationDescription(Algorithm.AES, CipherMode.GCM, Padding.NONE, 128), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.GCM, Padding.NONE, AES_128_KEY_LENGTH);
					return true;
				})
				.add("aes-192-gcm", transformationDescription(Algorithm.AES, CipherMode.GCM, Padding.NONE, 192), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.GCM, Padding.NONE, AES_192_KEY_LENGTH);
					return true;
				})
				.add("aes-256-gcm", transformationDescription(Algorithm.AES, CipherMode.GCM, Padding.NONE, 256), (p) -> {
					setTransformation(Algorithm.AES, CipherMode.GCM, Padding.NONE, AES_256_KEY_LENGTH);
					return true;
				})
				.add("md5", "digest: MD5 (16 bytes long)", (p) -> {
					setDigestMode(Algorithm.MD5);
					return true;
				})
				.add("sha1", "digest: SHA1 (20 bytes long)", (p) -> {
					setDigestMode(Algorithm.SHA1);
					return true;
				})
				.add("sha256", "digest: SHA256 (32 bytes long)", (p) -> {
					setDigestMode(Algorithm.SHA256);
					return true;
				})
				.add("sha384", "digest: SHA384 (48 bytes long)", (p) -> {
					setDigestMode(Algorithm.SHA384);
					return true;
				})
				.add("sha512", "digest: SHA512 (64 bytes long)", (p) -> {
					setDigestMode(Algorithm.SHA512);
					return true;
				})
				.add("-encrypt", "sets operation mode to encryption", (p) -> {
					setOperation(Cipher.ENCRYPT_MODE);
					return true;
				})
				.add("-decrypt", "sets operation mode to decryption", (p) -> {
					setOperation(Cipher.DECRYPT_MODE);
					return true;
				})
				.add("-input", "PATH", "specifies input file path\nreads from standard input if a hyphen is specified", (p) -> {
					if (p.next()) {
						setInputPath(p.argument());
						return true;
					} else {
						throw new RuntimeException("Input file is not specified.");
					}
				})
				.add("-output", "PATH", "specifies output file path\nwrites to standard output if a hyphen is specified", (p) -> {
					if (p.next()) {
						setOutputPath(p.argument());
						return true;
					} else {
						throw new RuntimeException("Output file is not specified.");
					}
				})
				.add("-passphrase", "TEXT", "specifies passphrase to generate key", (p) -> {
					if (p.next()) {
						if (!hasPassphrase()) {
							setPassphrase(p.argument());
							return true;
						} else {
							throw new RuntimeException("Private key is already specified.");
						}
					} else {
						throw new RuntimeException("Key phrase is not specified.");
					}
				})
				.add("-key", "HEX", "specifies private key", (p) -> {
					if (p.next()) {
						if (!hasKey()) {
							setKey(p.binaryArgument());
							return true;
						} else {
							throw new RuntimeException("Private key is already specified.");
						}
					} else {
						throw new RuntimeException("Private key is not specified.");
					}
				})
				.add("-iv", "HEX", "specifies initial vector", (p) -> {
					if (p.next()) {
						if (!hasIv()) {
							setIv(p.binaryArgument());
							return true;
						} else {
							throw new RuntimeException("Initial vector is already specified.");
						}
					} else {
						throw new RuntimeException("Initial vector is not specified.");
					}
				})
				.add("-nonce", "HEX", "specifies nonce for AEAD", (p) -> {
					if (p.next()) {
						if (!hasNonce()) {
							setNonce(p.binaryArgument());
							return true;
						} else {
							throw new RuntimeException("Nonce is already specified.");
						}
					} else {
						throw new RuntimeException("Nonce is not specified.");
					}
				})
				.add("-aad", "TEXT", "specifies additional authenticated data for AEAD", (p) -> {
					if (p.next()) {
						if (!hasAAD()) {
							setAad(p.argument().getBytes());
							return true;
						} else {
							throw new RuntimeException("Additional authentication data is already specified.");
						}
					} else {
						throw new RuntimeException("Additional authentication data is not specified with text.");
					}
				})
				.add("-taglength", "NUM", String.format("specifies tag length for AEAD\ndefault: gcm=%d", AES_GCM_TAG_LENGTH_DEFAULT), (p) -> {
					if (p.next()) {
						if (!hasTagLength()) {
							setTagLength(p.intArgument());
						} else {
							throw new RuntimeException("Tag length is already specified.");
						}
						return true;
					} else {
						throw new RuntimeException("Tag length is not specified.");
					}
				})
				.add("-help", "prints this message", (p) -> {
					help(p);
					return false;
				})
				.addAlias("-e", "-encrypt")
				.addAlias("-d", "-decrypt")
				.addAlias("-i", "-input")
				.addAlias("-o", "-output")
				.addAlias("-p", "-passphrase")
				.addAlias("-k", "-key")
				.addAlias("-v", "-iv")
				.addAlias("-n", "-nonce")
				.addAlias("-a", "-aad")
				.addAlias("-T", "-taglength")
				.addAlias("-h", "-help");
	}

	private static String transformationDescription(Algorithm algorithm, CipherMode mode, Padding padding, int keyBits) {
		if (mode.useNonce()) {
			return String.format("cipher: %s [%s] key=%d nonce=%d tag=%d", algorithm.label(), mode.description(), keyBits / 8, AES_GCM_NONCE_LENGTH, AES_GCM_TAG_LENGTH_DEFAULT);
		} else if (mode.useIV()) {
			return String.format("cipher: %s [%s] key=%d iv=%d padding=%s", algorithm.label(), mode.description(), keyBits / 8, AES_IV_LENGTH, padding.description());
		} else {
				return String.format("cipher: %s [%s] key=%d padding=%s", algorithm.label(), mode.description(), keyBits / 8, padding.description());
		}
	}

	private void cleanup() {
		if (_tmpPath != null) {
			try {
				if (Files.exists(_tmpPath)) {
					Files.delete(_tmpPath);
				}
			} catch (Exception e) {
				printError(e);
			}
		}
	}

	public static void main(String[] args) {
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		try {
			CommandLineParameters parameters = app.commandLineParameters();
			if (args.length == 0) {
				help(parameters);
			} else if (parameters.process(args)) {
				app.run();
			}
			System.exit(0);
		} catch (Throwable t) {
			printError(t);
			System.exit(1);
		} finally {
			app.cleanup();
		}
	}

	private static void help(CommandLineParameters parameters) {
		System.out.printf(DESCRIPTION, VERSION);
		System.out.printf("%s", parameters);
	}

	private static void printError(Throwable t) {
		System.err.printf("ERROR: %s\n", t.getMessage());
		while ((t = t.getCause()) != null) {
			System.err.printf("       %s\n", t.getMessage());
		}
	}

}
