package com.hideakin.mycrypto;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.Before;
import org.junit.Test;

import com.hideakin.util.HexString;

public class MyCryptographyUtilityTest {

	private static final String DATA1 = "0123456789ABCDEF";
	private static final String DATA2 = "0123456789ABCDEFG";
	private static final String DATA3 = "月が手前を通過することによって土星が隠れる天文現象「土星食」が8日夜、観測された。";
	private static final String DATA4 = "今季Ｊ１初挑戦で３位と躍進した町田からは選出ゼロとなった。";

	private static final String TMPDIR = Paths.get(System.getProperty("java.io.tmpdir"), "MyCryptographyUtilityTest").toString();

	@Before
	public void setUp() throws Exception {
		Path path = Paths.get(TMPDIR);
		if (Files.exists(path)) {
			Files.list(path).forEach((p) -> {
				try {
					//System.out.printf("deleting %s\n", p);
					Files.delete(p);
				} catch (Exception e) {
					System.out.printf("ERROR: %s\n", e.getMessage());
				}
			});
		} else {
			Files.createDirectory(path);
		}
	}

	@Test
	public void test_cbc_1_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cbc_1_1.in");
		Path outPath = Paths.get(TMPDIR, "test_cbc_1_1.out");
		byte[] inData = DATA1.getBytes(StandardCharsets.UTF_8);
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-cbc", "-e",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-p", "xyzzy",
				"-iv", "F88B0C6B6E48BE6A9150BA6A56E08290"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("#CBC-1-1\n");
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("F88B0C6B6E48BE6A9150BA6A56E082907827BCF03EC90507A5ADD010163ADA6304020CB0D0B21A684826D4324630FCB7", actual);
	}

	@Test
	public void test_cbc_1_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cbc_1_2.in");
		Path outPath = Paths.get(TMPDIR, "test_cbc_1_2.out");
		byte[] inData = HexString.parse("F88B0C6B6E48BE6A9150BA6A56E082907827BCF03EC90507A5ADD010163ADA6304020CB0D0B21A684826D4324630FCB7");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-cbc", "-d",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-key", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED622F5EE078671AED"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		assertEquals(16, result.length);
		String actual = new String(result, StandardCharsets.UTF_8);
		System.out.printf("#CBC-1-2\n");
		System.out.printf("#%s\n", actual);
		assertEquals(DATA1, actual);
	}

	@Test
	public void test_cbc_2_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cbc_2_1.in");
		Path outPath = Paths.get(TMPDIR, "test_cbc_2_1.out");
		byte[] inData = DATA2.getBytes(StandardCharsets.UTF_8);
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-cbc", "-e",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-key", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED622F5EE078671AED",
				"-iv", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("#CBC-2-1\n");
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("B87E2F0E1BEB474894C501960ECBE847C3578853E13E75D944113C4637BFD5FA31534153CB71E59ECF786D3F0A4814D1", actual);
	}

	@Test
	public void test_cbc_2_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cbc_2_2.in");
		Path outPath = Paths.get(TMPDIR, "test_cbc_2_2.out");
		byte[] inData = HexString.parse("B87E2F0E1BEB474894C501960ECBE847C3578853E13E75D944113C4637BFD5FA31534153CB71E59ECF786D3F0A4814D1");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-cbc", "-d",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-p", "xyzzy"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		assertEquals(17, result.length);
		String actual = new String(result, StandardCharsets.UTF_8);
		System.out.printf("#CBC-2-2\n");
		System.out.printf("#%s\n", actual);
		assertEquals(DATA2, actual);
	}

	@Test
	public void test_cbc_3_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cbc_3_1.in");
		Path outPath = Paths.get(TMPDIR, "test_cbc_3_1.out");
		byte[] inData = DATA3.getBytes(StandardCharsets.UTF_8);
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-192-cbc", "-e",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-p", "xyzzy",
				"-iv", "F88B0C6B6E48BE6A9150BA6A56E08290"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("#CBC-3-1\n");
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("F88B0C6B6E48BE6A9150BA6A56E082907E72A53E9D7FDBC163CDE54407CDA3EFE46C2E0F48CA83B013053DC4275C4339B4999E5F46C614C0FDF5DA74747AF54BADC9C69BFB913429BEDFC87532A48D130D9F3709381E1C785CB8B50B9E80473CC1E6B65E4E31881EEDEC2F7178521173479AC3503A49F0A71941A00183519A3E9B1B859A6CBE705F553AAAA79ACD548B", actual);
	}

	@Test
	public void test_cbc_3_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cbc_3_2.in");
		Path outPath = Paths.get(TMPDIR, "test_cbc_3_2.out");
		byte[] inData = HexString.parse("F88B0C6B6E48BE6A9150BA6A56E082907E72A53E9D7FDBC163CDE54407CDA3EFE46C2E0F48CA83B013053DC4275C4339B4999E5F46C614C0FDF5DA74747AF54BADC9C69BFB913429BEDFC87532A48D130D9F3709381E1C785CB8B50B9E80473CC1E6B65E4E31881EEDEC2F7178521173479AC3503A49F0A71941A00183519A3E9B1B859A6CBE705F553AAAA79ACD548B");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-192-cbc", "-d",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = new String(result, StandardCharsets.UTF_8);
		System.out.printf("#CBC-3-2\n");
		System.out.printf("#%s\n", actual);
		assertEquals(DATA3, actual);
	}

	@Test
	public void test_cbc_4_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cbc_4_1.in");
		Path outPath = Paths.get(TMPDIR, "test_cbc_4_1.out");
		byte[] inData = DATA4.getBytes(StandardCharsets.UTF_8);
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-128-cbc", "-e",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-p", "xyzzy",
				"-iv", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("#CBC-4-1\n");
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("B87E2F0E1BEB474894C501960ECBE847766A42A99FD13987CA0D315EBCABB00F3DE7D2383FD88860360DFDD1BC13A5D620B26C7396F0FAA3AAD542C1BA404387C5990CAEBBC18DE3F7BCCA5E0E11B618A0A7B84B1BA1C8B947641B53E45D63F3362195206F9A8C641F1549E3C7FA2EEC", actual);
	}

	@Test
	public void test_cbc_4_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cbc_4_2.in");
		Path outPath = Paths.get(TMPDIR, "test_cbc_4_2.out");
		byte[] inData = HexString.parse("B87E2F0E1BEB474894C501960ECBE847766A42A99FD13987CA0D315EBCABB00F3DE7D2383FD88860360DFDD1BC13A5D620B26C7396F0FAA3AAD542C1BA404387C5990CAEBBC18DE3F7BCCA5E0E11B618A0A7B84B1BA1C8B947641B53E45D63F3362195206F9A8C641F1549E3C7FA2EEC");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-128-cbc", "-d",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = new String(result, StandardCharsets.UTF_8);
		System.out.printf("#CBC-4-2\n");
		System.out.printf("#%s\n", actual);
		assertEquals(DATA4, actual);
	}

	@Test
	public void test_cbc_5_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cbc_5_1.in");
		Path outPath = Paths.get(TMPDIR, "test_cbc_5_1.out");
		byte[] inData = DATA3.getBytes(StandardCharsets.UTF_8);
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-cbc", "-e",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-p", "xyzzy",
				"-iv", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("#CBC-5-1\n");
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("B87E2F0E1BEB474894C501960ECBE8477B71A870DAB0C286DB0FD6F5A6CB6DA67FB1AAF50B1E552204ED46EDF2B434619EF512C5F74BBA4ABBBD76D540D97642CC7AFC5DF121322D7946488982A83E98BEEBB22A759F89C7DAAADFC8E7D1A0104540393CD97D5B39167B3C3C0BAFC1BCA0A69384F2ECC08237A71E34D6A77A0A191300ADA83E3504A96EACE0939169B8", actual);
	}

	@Test
	public void test_cbc_5_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cbc_5_2.in");
		Path outPath = Paths.get(TMPDIR, "test_cbc_5_2.out");
		byte[] inData = HexString.parse("B87E2F0E1BEB474894C501960ECBE8477B71A870DAB0C286DB0FD6F5A6CB6DA67FB1AAF50B1E552204ED46EDF2B434619EF512C5F74BBA4ABBBD76D540D97642CC7AFC5DF121322D7946488982A83E98BEEBB22A759F89C7DAAADFC8E7D1A0104540393CD97D5B39167B3C3C0BAFC1BCA0A69384F2ECC08237A71E34D6A77A0A191300ADA83E3504A96EACE0939169B8");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-cbc", "-d",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED622F5EE078671AED"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = new String(result, StandardCharsets.UTF_8);
		System.out.printf("#CBC-5-2\n");
		System.out.printf("#%s\n", actual);
		assertEquals(DATA3, actual);
	}

	@Test
	public void test_ecb_1_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ecb_1_1.in");
		Path outPath = Paths.get(TMPDIR, "test_ecb_1_1.out");
		byte[] inData = DATA1.getBytes(StandardCharsets.UTF_8);
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-ecb", "-e",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-p", "xyzzy"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("#ECB-1-1\n");
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("DAD0BC105BCD60F44B5E86DF21C86E7E85F7AD59268F6C527045AF291ABBB2D0", actual);
	}

	@Test
	public void test_ecb_1_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ecb_1_2.in");
		Path outPath = Paths.get(TMPDIR, "test_ecb_1_2.out");
		byte[] inData = HexString.parse("DAD0BC105BCD60F44B5E86DF21C86E7E85F7AD59268F6C527045AF291ABBB2D0");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-ecb", "-d",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED622F5EE078671AED"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		assertEquals(16, result.length);
		String actual = new String(result, StandardCharsets.UTF_8);
		System.out.printf("#ECB-1-2\n");
		System.out.printf("#%s\n", actual);
		assertEquals(DATA1, actual);
	}

	@Test
	public void test_ecb_2_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ecb_2_1.in");
		Path outPath = Paths.get(TMPDIR, "test_ecb_2_1.out");
		byte[] inData = DATA2.getBytes(StandardCharsets.UTF_8);
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-ecb", "-e",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED622F5EE078671AED"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("#ECB-2-1\n");
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("DAD0BC105BCD60F44B5E86DF21C86E7ED47E47A949514837921F398CF2878899", actual);
	}

	@Test
	public void test_ecb_2_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ecb_2_2.in");
		Path outPath = Paths.get(TMPDIR, "test_ecb_2_2.out");
		byte[] inData = HexString.parse("DAD0BC105BCD60F44B5E86DF21C86E7ED47E47A949514837921F398CF2878899");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-ecb", "-d",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-p", "xyzzy"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		assertEquals(17, result.length);
		String actual = new String(result, StandardCharsets.UTF_8);
		System.out.printf("#ECB-2-2\n");
		System.out.printf("#%s\n", actual);
		assertEquals(DATA2, actual);
	}

	@Test
	public void test_ecb_3_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ecb_3_1.in");
		Path outPath = Paths.get(TMPDIR, "test_ecb_3_1.out");
		byte[] inData = DATA3.getBytes(StandardCharsets.UTF_8);
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-192-ecb", "-e",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-p", "xyzzy"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("#ECB-3-1\n");
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("3DA412BFA0D645A0708389D59BFC6DFCAC1CC582011F02E946212B556ABDCAFA23E4049C05C3DE3B7B4D0F5E8D684C013FE749491AAF2F948E382083F2210C07D13F926A74A0EBADC59505B2F58BA5E8E2EBECDBA276F3DC84AB4F9F22EBCAB5A4109EFBCF64749952733E7D749A5CC6A5F2CF40B976E2837482657B6B21EF8D", actual);
	}

	@Test
	public void test_ecb_3_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ecb_3_2.in");
		Path outPath = Paths.get(TMPDIR, "test_ecb_3_2.out");
		byte[] inData = HexString.parse("3DA412BFA0D645A0708389D59BFC6DFCAC1CC582011F02E946212B556ABDCAFA23E4049C05C3DE3B7B4D0F5E8D684C013FE749491AAF2F948E382083F2210C07D13F926A74A0EBADC59505B2F58BA5E8E2EBECDBA276F3DC84AB4F9F22EBCAB5A4109EFBCF64749952733E7D749A5CC6A5F2CF40B976E2837482657B6B21EF8D");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-192-ecb", "-d",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = new String(result, StandardCharsets.UTF_8);
		System.out.printf("#ECB-3-2\n");
		System.out.printf("#%s\n", actual);
		assertEquals(DATA3, actual);
	}

	@Test
	public void test_ecb_4_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ecb_4_1.in");
		Path outPath = Paths.get(TMPDIR, "test_ecb_4_1.out");
		byte[] inData = DATA4.getBytes(StandardCharsets.UTF_8);
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-128-ecb", "-e",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-p", "xyzzy"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("#ECB-4-1\n");
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("2D84DB6C70C7D74A193AD5AA5E3916A5B92B4702CE98346F6E73DE64B42A2D62A4E39AF48FE2F75DCCEA9091B6C7C45F7576995E907A8BDBD05D7419AA766A331261149BA9B5CE7E1A7E26D6ECAC718864D8B794865876075F0942FC929C29FD", actual);
	}

	@Test
	public void test_ecb_4_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ecb_4_2.in");
		Path outPath = Paths.get(TMPDIR, "test_ecb_4_2.out");
		byte[] inData = HexString.parse("2D84DB6C70C7D74A193AD5AA5E3916A5B92B4702CE98346F6E73DE64B42A2D62A4E39AF48FE2F75DCCEA9091B6C7C45F7576995E907A8BDBD05D7419AA766A331261149BA9B5CE7E1A7E26D6ECAC718864D8B794865876075F0942FC929C29FD");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-128-ecb", "-d",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = new String(result, StandardCharsets.UTF_8);
		System.out.printf("#ECB-4-2\n");
		System.out.printf("#%s\n", actual);
		assertEquals(DATA4, actual);
	}

	@Test
	public void test_cfb_1_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cfb_1_1.in");
		Path outPath = Paths.get(TMPDIR, "test_cfb_1_1.out");
		byte[] inData = DATA1.getBytes(StandardCharsets.UTF_8);
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-cfb", "-e",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-p", "xyzzy",
				"-v", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("#CFB-1-1\n");
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("B87E2F0E1BEB474894C501960ECBE84749087F96EDE81A95E4EA7B10C0A6BC79", actual);
	}

	@Test
	public void test_cfb_1_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cfb_1_2.in");
		Path outPath = Paths.get(TMPDIR, "test_cfb_1_2.out");
		byte[] inData = HexString.parse("B87E2F0E1BEB474894C501960ECBE84749087F96EDE81A95E4EA7B10C0A6BC79");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-cfb", "-d",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED622F5EE078671AED"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		assertEquals(16, result.length);
		String actual = new String(result, StandardCharsets.UTF_8);
		System.out.printf("#CFB-1-2\n");
		System.out.printf("#%s\n", actual);
		assertEquals(DATA1, actual);
	}

	@Test
	public void test_cfb_2_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cfb_2_1.in");
		Path outPath = Paths.get(TMPDIR, "test_cfb_2_1.out");
		byte[] inData = DATA2.getBytes(StandardCharsets.UTF_8);
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-cfb", "-e",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-key", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED622F5EE078671AED",
				"-iv", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("#CFB-2-1\n");
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("B87E2F0E1BEB474894C501960ECBE84749087F96EDE81A95E4EA7B10C0A6BC791D", actual);
	}

	@Test
	public void test_cfb_2_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cfb_2_2.in");
		Path outPath = Paths.get(TMPDIR, "test_cfb_2_2.out");
		byte[] inData = HexString.parse("B87E2F0E1BEB474894C501960ECBE84749087F96EDE81A95E4EA7B10C0A6BC791D");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-cfb", "-d",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-p", "xyzzy"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		assertEquals(17, result.length);
		String actual = new String(result, StandardCharsets.UTF_8);
		System.out.printf("#CFB-2-2\n");
		System.out.printf("#%s\n", actual);
		assertEquals(DATA2, actual);
	}

	@Test
	public void test_cfb_3_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cfb_3_1.in");
		Path outPath = Paths.get(TMPDIR, "test_cfb_3_1.out");
		byte[] inData = DATA3.getBytes(StandardCharsets.UTF_8);
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-192-cfb", "-e",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-p", "xyzzy",
				"-iv", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("#CFB-3-1\n");
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("B87E2F0E1BEB474894C501960ECBE847B7CEADB2254B852D1DFDA30A2CE482B8295DE359DD85F4F4B427C222CF21E323D81905443C478280A72CA0B1AB50200EC017C2F52B845E7408E0D2EAC5217FFCF938C9756E01E96FE655DE16C96A938CA16FEA6D4950015E8CC1B1CD6883C4A9E14B07BF7592236444F07A689F75B2DD9D70BDFF78B8C3383B", actual);
	}

	@Test
	public void test_cfb_3_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cfb_3_2.in");
		Path outPath = Paths.get(TMPDIR, "test_cfb_3_2.out");
		byte[] inData = HexString.parse("B87E2F0E1BEB474894C501960ECBE847B7CEADB2254B852D1DFDA30A2CE482B8295DE359DD85F4F4B427C222CF21E323D81905443C478280A72CA0B1AB50200EC017C2F52B845E7408E0D2EAC5217FFCF938C9756E01E96FE655DE16C96A938CA16FEA6D4950015E8CC1B1CD6883C4A9E14B07BF7592236444F07A689F75B2DD9D70BDFF78B8C3383B");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-192-cfb", "-d",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-key", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = new String(result, StandardCharsets.UTF_8);
		System.out.printf("#CFB-3-2\n");
		System.out.printf("#%s\n", actual);
		assertEquals(DATA3, actual);
	}

	@Test
	public void test_cfb_4_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cfb_4_1.in");
		Path outPath = Paths.get(TMPDIR, "test_cfb_4_1.out");
		byte[] inData = DATA4.getBytes(StandardCharsets.UTF_8);
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-128-cfb", "-e",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-p", "xyzzy",
				"-iv", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("#CFB-4-1\n");
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("B87E2F0E1BEB474894C501960ECBE8475609DF57AD1D858598414CCB11B3DAC8D9E63F8775D9521474216EED5BA06C587641F58DCDC5D9AEB551A97F586C17FAFE30F201790F34276EA2508F92B66B3B82B205DF26814E138BC4E2CC8568DE6EB697528743B7AD", actual);
	}

	@Test
	public void test_cfb_4_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_cfb_4_2.in");
		Path outPath = Paths.get(TMPDIR, "test_cfb_4_2.out");
		byte[] inData = HexString.parse("B87E2F0E1BEB474894C501960ECBE8475609DF57AD1D858598414CCB11B3DAC8D9E63F8775D9521474216EED5BA06C587641F58DCDC5D9AEB551A97F586C17FAFE30F201790F34276EA2508F92B66B3B82B205DF26814E138BC4E2CC8568DE6EB697528743B7AD");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-128-cfb", "-d",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-key", "184858A00FD7971F810848266EBCECEE"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = new String(result, StandardCharsets.UTF_8);
		System.out.printf("#CFB-4-2\n");
		System.out.printf("#%s\n", actual);
		assertEquals(DATA4, actual);
	}

	@Test
	public void test_ofb_1_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ofb_1_1.in");
		Path outPath = Paths.get(TMPDIR, "test_ofb_1_1.out");
		byte[] inData = DATA1.getBytes(StandardCharsets.UTF_8);
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-ofb", "-e",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-p", "xyzzy",
				"-v", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("#OFB-1-1\n");
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("B87E2F0E1BEB474894C501960ECBE84749087F96EDE81A95E4EA7B10C0A6BC79", actual);
	}

	@Test
	public void test_ofb_1_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ofb_1_2.in");
		Path outPath = Paths.get(TMPDIR, "test_ofb_1_2.out");
		byte[] inData = HexString.parse("B87E2F0E1BEB474894C501960ECBE84749087F96EDE81A95E4EA7B10C0A6BC79");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-ofb", "-d",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED622F5EE078671AED"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		assertEquals(16, result.length);
		String actual = new String(result, StandardCharsets.UTF_8);
		System.out.printf("#OFB-1-2\n");
		System.out.printf("#%s\n", actual);
		assertEquals(DATA1, actual);
	}

	@Test
	public void test_ofb_2_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ofb_2_1.in");
		Path outPath = Paths.get(TMPDIR, "test_ofb_2_1.out");
		byte[] inData = DATA2.getBytes(StandardCharsets.UTF_8);
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-ofb", "-e",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED622F5EE078671AED",
				"-v", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("#OFB-2-1\n");
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("B87E2F0E1BEB474894C501960ECBE84749087F96EDE81A95E4EA7B10C0A6BC79C8", actual);
	}

	@Test
	public void test_ofb_2_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ofb_2_2.in");
		Path outPath = Paths.get(TMPDIR, "test_ofb_2_2.out");
		byte[] inData = HexString.parse("B87E2F0E1BEB474894C501960ECBE84749087F96EDE81A95E4EA7B10C0A6BC79C8");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-ofb", "-d",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-p", "xyzzy"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		assertEquals(17, result.length);
		String actual = new String(result, StandardCharsets.UTF_8);
		System.out.printf("#OFB-2-2\n");
		System.out.printf("#%s\n", actual);
		assertEquals(DATA2, actual);
	}

	@Test
	public void test_ofb_3_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ofb_3_1.in");
		Path outPath = Paths.get(TMPDIR, "test_ofb_3_1.out");
		byte[] inData = DATA3.getBytes(StandardCharsets.UTF_8);
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-192-ofb", "-e",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-p", "xyzzy",
				"-v", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("#OFB-3-1\n");
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("B87E2F0E1BEB474894C501960ECBE847B7CEADB2254B852D1DFDA30A2CE482B8CB1FC67380A97C192FC9CBD055B000C1406AED0E5EBFEB9219B6C2530ECEABF4FA64A953D1B34521802B4A017B3481A526242A4D25CF6C5398A487E6B265A015FBEA1707BD9ABAFAF70A553904EE94E995D4F37FB4179E95608DC62F461B84357F1F4BD2A7F579736E", actual);
	}

	@Test
	public void test_ofb_3_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ofb_3_2.in");
		Path outPath = Paths.get(TMPDIR, "test_ofb_3_2.out");
		byte[] inData = HexString.parse("B87E2F0E1BEB474894C501960ECBE847B7CEADB2254B852D1DFDA30A2CE482B8CB1FC67380A97C192FC9CBD055B000C1406AED0E5EBFEB9219B6C2530ECEABF4FA64A953D1B34521802B4A017B3481A526242A4D25CF6C5398A487E6B265A015FBEA1707BD9ABAFAF70A553904EE94E995D4F37FB4179E95608DC62F461B84357F1F4BD2A7F579736E");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-192-ofb", "-d",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = new String(result, StandardCharsets.UTF_8);
		System.out.printf("#OFB-3-2\n");
		System.out.printf("#%s\n", actual);
		assertEquals(DATA3, actual);
	}

	@Test
	public void test_ofb_4_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ofb_4_1.in");
		Path outPath = Paths.get(TMPDIR, "test_ofb_4_1.out");
		byte[] inData = DATA4.getBytes(StandardCharsets.UTF_8);
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-128-ofb", "-e",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-p", "xyzzy",
				"-v", "B87E2F0E1BEB474894C501960ECBE847"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("#OFB-4-1\n");
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("B87E2F0E1BEB474894C501960ECBE8475609DF57AD1D858598414CCB11B3DAC850F6B454DE22D975BF187095ABBEE953E42CA76C032C54BF6025F19E7C2753A24E13465B82344FD024168F4A02D728066DF8D59B6DFB5D4FE7FA57D0ADC11540C6D1251628CBA6", actual);
	}

	@Test
	public void test_ofb_4_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_ofb_4_2.in");
		Path outPath = Paths.get(TMPDIR, "test_ofb_4_2.out");
		byte[] inData = HexString.parse("B87E2F0E1BEB474894C501960ECBE8475609DF57AD1D858598414CCB11B3DAC850F6B454DE22D975BF187095ABBEE953E42CA76C032C54BF6025F19E7C2753A24E13465B82344FD024168F4A02D728066DF8D59B6DFB5D4FE7FA57D0ADC11540C6D1251628CBA6");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-128-ofb", "-d",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = new String(result, StandardCharsets.UTF_8);
		System.out.printf("#OFB-4-2\n");
		System.out.printf("#%s\n", actual);
		assertEquals(DATA4, actual);
	}

	@Test
	public void test_gcm_1_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_gcm_1_1.in");
		Path outPath = Paths.get(TMPDIR, "test_gcm_1_1.out");
		byte[] inData = DATA1.getBytes(StandardCharsets.UTF_8);
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-gcm", "-e",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-p", "xyzzy",
				"-n", "B87E2F0E1BEB474894C50196"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("#GCM-1-1\n");
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("B87E2F0E1BEB474894C5019690F4BD9F6459EF502B2515BDE45F915FBBA1FDFCB8BAB5E704350CD6AE5E0602", actual);
	}

	@Test
	public void test_gcm_1_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_gcm_1_2.in");
		Path outPath = Paths.get(TMPDIR, "test_gcm_1_2.out");
		byte[] inData = HexString.parse("B87E2F0E1BEB474894C5019690F4BD9F6459EF502B2515BDE45F915FBBA1FDFCB8BAB5E704350CD6AE5E0602");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-gcm", "-d",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED622F5EE078671AED"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		assertEquals(16, result.length);
		String actual = new String(result, StandardCharsets.UTF_8);
		System.out.printf("#GCM-1-2\n");
		System.out.printf("#%s\n", actual);
		assertEquals(DATA1, actual);
	}

	@Test
	public void test_gcm_2_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_gcm_2_1.in");
		Path outPath = Paths.get(TMPDIR, "test_gcm_2_1.out");
		byte[] inData = DATA2.getBytes(StandardCharsets.UTF_8);
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-gcm", "-e",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED622F5EE078671AED",
				"-n", "B87E2F0E1BEB474894C50196",
				"-a", "I'll be back."
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("#GCM-2-1\n");
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("B87E2F0E1BEB474894C5019690F4BD9F6459EF502B2515BDE45F915F8B04EA7D05286B4745639E7CA745FEF6C7", actual);
	}

	@Test
	public void test_gcm_2_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_gcm_2_2.in");
		Path outPath = Paths.get(TMPDIR, "test_gcm_2_2.out");
		byte[] inData = HexString.parse("B87E2F0E1BEB474894C5019690F4BD9F6459EF502B2515BDE45F915F8B04EA7D05286B4745639E7CA745FEF6C7");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-256-gcm", "-d",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-p", "xyzzy",
				"-a", "I'll be back."
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		assertEquals(17, result.length);
		String actual = new String(result, StandardCharsets.UTF_8);
		System.out.printf("#GCM-2-2\n");
		System.out.printf("#%s\n", actual);
		assertEquals(DATA2, actual);
	}

	@Test
	public void test_gcm_3_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_gcm_3_1.in");
		Path outPath = Paths.get(TMPDIR, "test_gcm_3_1.out");
		byte[] inData = DATA3.getBytes(StandardCharsets.UTF_8);
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-192-gcm", "-e",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-p", "xyzzy",
				"-n", "B87E2F0E1BEB474894C50196",
				"-taglength", "13"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("#GCM-3-1\n");
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("B87E2F0E1BEB474894C50196E1BECF982A99D227151CA4B249D76284DF40A963FCAB33DCF6409E2F43F084025C1EBF90DA96C1429151026A898B515EAA6CA8F8B2F994AC85457E2BCF2F0D08D3987ABD37033E5617A849E329CF3CDAC47E67EC2236497888258C57FFAC70A82553AF4217EC00597D57C076EBEC0A1E971AE807B1C054735C582BED3BCC3FAFB3A462ADD8AD", actual);
	}

	@Test
	public void test_gcm_3_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_gcm_3_2.in");
		Path outPath = Paths.get(TMPDIR, "test_gcm_3_2.out");
		byte[] inData = HexString.parse("B87E2F0E1BEB474894C50196E1BECF982A99D227151CA4B249D76284DF40A963FCAB33DCF6409E2F43F084025C1EBF90DA96C1429151026A898B515EAA6CA8F8B2F994AC85457E2BCF2F0D08D3987ABD37033E5617A849E329CF3CDAC47E67EC2236497888258C57FFAC70A82553AF4217EC00597D57C076EBEC0A1E971AE807B1C054735C582BED3BCC3FAFB3A462ADD8AD");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-192-gcm", "-d",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE5E8B69972C5FFAED",
				"-taglength", "13"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = new String(result, StandardCharsets.UTF_8);
		System.out.printf("#GCM-3-2\n");
		System.out.printf("#%s\n", actual);
		assertEquals(DATA3, actual);
	}

	@Test
	public void test_gcm_4_1() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_gcm_4_1.in");
		Path outPath = Paths.get(TMPDIR, "test_gcm_4_1.out");
		byte[] inData = DATA4.getBytes(StandardCharsets.UTF_8);
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-128-gcm", "-e",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-p", "xyzzy",
				"-n", "B87E2F0E1BEB474894C50196",
				"-taglength", "14",
				"-a", "吉田沙保里さん（４２）が、連日の活躍で観客を沸かせた。"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = HexString.toString(result);
		System.out.printf("#GCM-4-1\n");
		System.out.printf("# IN %s\n", HexString.toString(inData));
		System.out.printf("#OUT %s\n", actual);
		assertEquals("B87E2F0E1BEB474894C5019673CEA4A1B4D89635654B8F450C42F238BA1668FBD47944353D8FBC10E05FAAF3F03E726427071CD80536F606612CFD57F64161AA40FE6AE7B601CD57E30A5D87511B01FCBD2E27B5D7D46B1ABC92AAAA58807F71D9E990FFE0B07AB74CE1D23AFDD9217017", actual);
	}

	@Test
	public void test_gcm_4_2() throws Exception {
		Path inPath = Paths.get(TMPDIR, "test_gcm_4_2.in");
		Path outPath = Paths.get(TMPDIR, "test_gcm_4_2.out");
		byte[] inData = HexString.parse("B87E2F0E1BEB474894C5019673CEA4A1B4D89635654B8F450C42F238BA1668FBD47944353D8FBC10E05FAAF3F03E726427071CD80536F606612CFD57F64161AA40FE6AE7B601CD57E30A5D87511B01FCBD2E27B5D7D46B1ABC92AAAA58807F71D9E990FFE0B07AB74CE1D23AFDD9217017");
		Files.write(inPath, inData);
		MyCryptographyUtilityApplication app = new MyCryptographyUtilityApplication();
		app.commandLineParameters().process(new String[] {
				"aes-128-gcm", "-d",
				"-i", inPath.toString(),
				"-o", outPath.toString(),
				"-k", "184858A00FD7971F810848266EBCECEE",
				"-taglength", "14",
				"-a", "吉田沙保里さん（４２）が、連日の活躍で観客を沸かせた。"
		});
		app.run();
		byte[] result = Files.readAllBytes(outPath);
		String actual = new String(result, StandardCharsets.UTF_8);
		System.out.printf("#GCM-4-2\n");
		System.out.printf("#%s\n", actual);
		assertEquals(DATA4, actual);
	}

}
