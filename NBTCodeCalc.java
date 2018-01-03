package bmwnavcodes;

import java.math.BigInteger;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.ArrayUtils;

public class NBTCodeCalc {

	private static String moduleStrNBTN="7F6318788CABCBAFBAFF5C58E201BD8F3C331A95B8AA145DEABEB82BFBE792B9D510158D83FBFB40ED7352A299018F305BD7F57C3328698EEF3BC2F9F43193EF6795DB28F8BA710FA561BF32ACB11D6252327059F476D8F1317371D3414EA04D7E55289BBFD0287B03E3A81EF75026761386D2E8840546F0CD671615B2344089"
			+"00";
	private static String expStrNBTN="0C695321EBA3156B39D0BC59357C0A7BAEBA606D9B2D80693951325E7FA57239"
			+"00";

	private static String expStrCIC="62784CB86637DE4FE8F8BE802760802EBD1FECDD993D966F3D21182FC7A72F86"
			+"00";
	private static String moduleStrCIC="2751EFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
			+"00";
	
	private static byte[] revByteArray(byte[] value ){
		ArrayUtils.reverse(value);
		return value;
	}
	
	public static String mainCalc(int navType, int region, int year, String vin, byte[] datainf ){

		String datainStr;
		String vinStr;
		String moduleStr;
		String expStr;

		if(navType==0){
		//CIC
			moduleStr = moduleStrCIC;
			expStr = expStrCIC;
			
		} else{
		//NBT
			moduleStr = moduleStrNBTN;
			expStr = expStrNBTN;
		}
		
		//TODO: check data validity


		//prepare data
		byte[] myData = Arrays.copyOfRange(datainf, 0x3E, 0x3E+0x80);
		datainStr = Hex.encodeHexString(myData)+"00";

		if(vin==null || vin.length()!=7){
		//TODO: get vin from datainf	
			return null;
		} else {
			vinStr=vin;
		}

		byte[] _region = new byte[2];//{0, 0x28};
		byte[] _year = new byte[2]; //{0, 0x05};

		_region[0]  = (byte)((region&0xFF00)>>8);
		_region[1]  = (byte)((region&0xFF));

		_year[0]  = (byte)((year&0xFF00)>>8);
		_year[1]  = (byte)((year&0xFF));

		byte[] vinB = vinStr.getBytes();
			
		
	try {

//Generate DES Key				
			BigInteger datain = new BigInteger(
					revByteArray(Hex.decodeHex(datainStr.toCharArray())));
	
			BigInteger module = new BigInteger(
					revByteArray(Hex.decodeHex(moduleStr.toCharArray())));
	
			BigInteger exp = new BigInteger(
					revByteArray(Hex.decodeHex(expStr.toCharArray())));
	
			BigInteger result = datain.modPow(exp, module);
	
			byte modpowRes[] = revByteArray(
					result.toByteArray());
			
			System.out.println(Hex.encodeHexString(modpowRes));
	
			//don't need leading zero in reversed
			if(modpowRes[modpowRes.length-1]==(byte)0x00)
				modpowRes = Arrays.copyOf(modpowRes, modpowRes.length-1);
	
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] thedigest = md.digest(modpowRes);
			//System.out.println(Hex.encodeHexString(thedigest));
			
			//2nd md5
			byte[] secondHash = new byte[0x13];
			System.arraycopy(vinB, 0, secondHash, 0, vinB.length);
			System.arraycopy(thedigest, 0, secondHash, 7, 8);
			System.arraycopy(_region, 0, secondHash, 15, 2);
			System.arraycopy(_year, 0, secondHash, 17, 2);
			byte[] the2digest = md.digest(secondHash);
			//System.out.println(Hex.encodeHexString(the2digest));
			
			//3rd md5
			byte[] triHash = new byte[0x10];
			System.arraycopy(thedigest, 0, triHash, 0, 8);
			System.arraycopy(the2digest, 0, triHash, 8, 8);
			byte[] the3digest = md.digest(triHash);
			//System.out.println(Hex.encodeHexString(the3digest));
			
			//7 times hashing md5 on the3digest
			for(int i =0;i<7;i++)
				the3digest = md.digest(the3digest);
			//System.out.println("7: "+Hex.encodeHexString(the3digest));
	
			// finally XOR first 8 bytes with second ones
			the3digest[0] ^= the3digest[8];
			the3digest[1] ^= the3digest[9];
			the3digest[2] ^= the3digest[10];
			the3digest[3] ^= the3digest[11];
			the3digest[4] ^= the3digest[12];
			the3digest[5] ^= the3digest[13];
			the3digest[6] ^= the3digest[14];
			the3digest[7] ^= the3digest[15];
	
			// result is 1st 8 bytes
			byte data0[] = new byte[12];
			data0[0] = 1;
			data0[1] = _region[0];
			data0[2] = _region[1];
			data0[3] = _year[0];
			data0[4] = _year[1];
			data0[5] = 1;
			data0[6] = 0;
			data0[7] = 0;
			data0[8] = _region[0];
			data0[9] = _region[1];
			data0[10] = _year[0];
			data0[11] = _year[1];
	
	//3DES
			byte _key[] = new byte[8];
			byte _data[] = new byte[8];
			System.arraycopy(the3digest, 0, _key,0, 8);
			System.arraycopy(data0, 0, _data, 0, 8);
			Key key = new SecretKeySpec(_key, "DES");
			Cipher cipher = Cipher.getInstance("DES");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] encrypted = cipher.doFinal(_data);
	
	//Base32		
			System.arraycopy(encrypted, 0, data0, 0, 8);
			System.out.println(Hex.encodeHexString(data0));
			String res = new Base32().encodeToString(data0);
			
			return (res.length()>20)?res.substring(0,20):res;
			
		} catch(Exception e){
			System.out.println("wrong data: "+e);
		}
			return null;
		}
}
