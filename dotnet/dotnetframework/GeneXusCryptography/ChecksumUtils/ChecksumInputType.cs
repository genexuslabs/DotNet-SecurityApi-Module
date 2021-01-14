using Org.BouncyCastle.Utilities.Encoders;
using SecurityAPICommons.Commons;
using SecurityAPICommons.Config;
using SecurityAPICommons.Utils;
using System;
using System.Security;
using System.Text;

namespace GeneXusCryptography.ChecksumUtils
{
	[SecuritySafeCritical]
	public enum ChecksumInputType
	{
		NONE, BASE64, HEX, TXT, ASCII,
	}

	[SecuritySafeCritical]
	public class ChecksumInputTypeUtils
	{
		public static ChecksumInputType getChecksumInputType(string checksumInputType, Error error)
		{
			switch (checksumInputType.ToUpper().Trim())
			{
				case "BASE64":
					return ChecksumInputType.BASE64;
				case "HEX":
					return ChecksumInputType.HEX;
				case "TXT":
					return ChecksumInputType.TXT;
				case "ASCII":
					return ChecksumInputType.ASCII;
				default:
					error.setError("CI001", "Unrecognized checksum input type");
					return ChecksumInputType.NONE;
			}
		}

		public static string valueOf(ChecksumInputType checksumInputType, Error error)
		{
			switch (checksumInputType)
			{
				case ChecksumInputType.BASE64:
					return "BASE64";
				case ChecksumInputType.HEX:
					return "HEX";
				case ChecksumInputType.TXT:
					return "TXT";
				case ChecksumInputType.ASCII:
					return "ASCII";
				default:
					error.setError("CI002", "Unrecognized checksum input type");
					return "";
			}
		}

		public static byte[] getBytes(ChecksumInputType checksumInputType, string input, Error error)
		{
			EncodingUtil eu = new EncodingUtil();
			byte[] aux = null;
			switch (checksumInputType)
			{
				case ChecksumInputType.BASE64:
					try
					{
						aux = Base64.Decode(input);
					}
					catch (Exception e)
					{
						error.setError("CI003", e.Message);
					}
					break;
				case ChecksumInputType.HEX:
					aux = SecurityUtils.GetHexa(input, "CI004", error);
					break;
				case ChecksumInputType.TXT:
					aux = eu.getBytes(input);
					if (eu.HasError())
					{
						error = eu.GetError();
					}
					break;
				case ChecksumInputType.ASCII:
					try
					{
						aux = new ASCIIEncoding().GetBytes(input);
					}
					catch (Exception e)
					{
						error.setError("CI004", e.Message);
					}
					break;
				default:
					error.setError("CI005", "Unrecognized checksum input type");
					break;
			}
			return aux;
		}
	}
}
