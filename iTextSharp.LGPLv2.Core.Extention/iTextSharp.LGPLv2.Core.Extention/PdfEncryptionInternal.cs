using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

namespace iTextSharp.text.pdf
{
	public class PdfEncryptionInternal : PdfEncryption
	{
		Type thisType;

		public PdfEncryptionInternal()
		{
			thisType = typeof(PdfEncryptionInternal);
		}

		public PdfEncryptionInternal(PdfEncryption enc) : base(enc)
		{
			thisType = typeof(PdfEncryptionInternal);
		}

		internal byte[] UserKey => (byte[])thisType.GetField("UserKey", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(this);
		internal int Permissions => (int)thisType.GetField("Permissions", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(this);
		public static readonly byte[] MetadataPad = { 255, 255, 255, 255 };
	}
}
