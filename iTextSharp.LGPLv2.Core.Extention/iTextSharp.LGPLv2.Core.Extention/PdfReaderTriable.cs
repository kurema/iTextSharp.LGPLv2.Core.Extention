using iTextSharp.text.exceptions;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.util;

namespace iTextSharp.text.pdf;

public class PdfReaderTriable : pdf.PdfReader
{
	//Type thisType;
	Type baseType;

	public void InitTypes()
	{
		//thisType = this.GetType();
		baseType = this.GetType().BaseType;
	}

	public PdfReaderTriable(string filename) : this(filename, null)
	{
	}

	public PdfReaderTriable(byte[] pdfIn) : this(pdfIn, null)
	{
	}

	public PdfReaderTriable(Uri url) : this(url, null)
	{
	}

	public PdfReaderTriable(PdfReader reader) : base(reader)
	{
		InitTypes();
	}

	public PdfReaderTriable(string filename, byte[] ownerPassword)
	{
		InitTypes();
		Password = ownerPassword;
		Tokens = new PrTokeniser(filename);
		ReadPdf();
	}

	public PdfReaderTriable(byte[] pdfIn, byte[] ownerPassword)
	{
		InitTypes();
		Password = ownerPassword;
		Tokens = new PrTokeniser(pdfIn);
		ReadPdf();
	}

	public PdfReaderTriable(Uri url, byte[] ownerPassword)
	{
		InitTypes();
		Password = ownerPassword;
		Tokens = new PrTokeniser(new RandomAccessFileOrArray(url));
		ReadPdf();
	}

	public PdfReaderTriable(Stream isp, bool forceRead = true) : this(isp, null, forceRead)
	{
	}

	//You cant't use this because ReadPdfPartial(); is used and it's not virtual.
	//public PdfReaderTriable(RandomAccessFileOrArray raf, byte[] ownerPassword) : base(raf, ownerPassword)
	//{
	//}

	public PdfReaderTriable(string filename, X509Certificate certificate, ICipherParameters certificateKey)
	{
		InitTypes();
		Certificate = certificate;
		CertificateKey = certificateKey;
		Tokens = new PrTokeniser(filename);
		ReadPdf();
	}

	public PdfReaderTriable(Stream isp, byte[] ownerPassword, bool forceRead = true)
	{
		InitTypes();
		Password = ownerPassword;
		Tokens = new PrTokeniser(new RandomAccessFileOrArray(isp, forceRead));
		ReadPdf();
	}

	public PdfReaderTriable(Stream isp, X509Certificate certificate, ICipherParameters certificateKey)
	{
		InitTypes();
		Certificate = certificate;
		CertificateKey = certificateKey;
		Tokens = new PrTokeniser(new RandomAccessFileOrArray(isp));
		ReadPdf();
	}

	protected internal PdfReaderTriable()
	{
		InitTypes();
	}


	protected override void ReadPdf()
	{
		try
		{
			baseType.GetProperty(nameof(FileLength)).SetValue(this, Tokens.File.Length);
			pdfVersion = Tokens.CheckPdfHeader();
			try
			{
				var _bBailout = (bool)baseType.GetField("_bBailout", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(this);
				if (_bBailout == false)
				{
					ReadXref();
				}
			}
			catch (Exception e)
			{
				try
				{
					Rebuilt = true;
					RebuildXref();
					lastXref = -1;
				}
				catch (Exception ne)
				{
					throw new InvalidPdfException("Rebuild failed: " + ne.Message + "; Original message: " + e.Message);
				}
			}

			try
			{
				var _bBailout = (bool)baseType.GetField("_bBailout", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(this);
				if (_bBailout == false)
				{
					ReadDocObjTriable();
				}
			}
			catch (Exception ne)
			{
				if (ne is BadPasswordExceptionTriable)
				{
					throw;
				}
				if (ne is BadPasswordException)
				{
					throw new BadPasswordException(ne.Message);
				}

				var _encryptionError = (bool)baseType.GetField("_encryptionError", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(this);
				if (Rebuilt || _encryptionError)
					if (Rebuilt)
					{
						throw;
					}

				Rebuilt = true;
				Encrypted = false;
				RebuildXref();
				lastXref = -1;
				ReadDocObjTriable();
			}

			Strings.Clear();
			ReadPages();
			EliminateSharedStreams();
			RemoveUnusedObjects();
		}
		finally
		{
			try
			{
				Tokens.Close();
			}
			catch
			{
				// empty on purpose
			}
		}
	}

	protected internal void ReadDocObjTriable()
	{
		List<PrStream> streams = new();
		var _xrefObj = new List<PdfObject>(Xref.Length / 2);
		baseType.GetField("_xrefObj", BindingFlags.NonPublic | BindingFlags.Instance).SetValue(this, _xrefObj);
		for (var k = 0; k < Xref.Length / 2; ++k)
		{
			_xrefObj.Add(null);
		}

		for (var k = 2; k < Xref.Length; k += 2)
		{
			var pos = Xref[k];
			if (pos <= 0 || Xref[k + 1] > 0)
			{
				continue;
			}

			Tokens.Seek(pos);
			Tokens.NextValidToken();
			if (Tokens.TokenType != PrTokeniser.TK_NUMBER)
			{
				Tokens.ThrowError("Invalid object number.");
			}

			var _objNum = Tokens.IntValue;
			Tokens.NextValidToken();
			if (Tokens.TokenType != PrTokeniser.TK_NUMBER)
			{
				Tokens.ThrowError("Invalid generation number.");
			}

			var _objGen = Tokens.IntValue;
			Tokens.NextValidToken();
			if (!Tokens.StringValue.Equals("obj", StringComparison.Ordinal))
			{
				Tokens.ThrowError("Token 'obj' expected.");
			}

			PdfObject obj;
			try
			{
				obj = ReadPrObject();
				if (obj.IsStream())
				{
					streams.Add((PrStream)obj);
				}
			}
			catch
			{
				obj = null;
			}

			_xrefObj[k / 2] = obj;
		}

		for (var k = 0; k < streams.Count; ++k)
		{
			baseType.GetMethod("checkPrStreamLength", BindingFlags.NonPublic | BindingFlags.Instance).Invoke(this, new[] { streams[k] });
		}

		readDecryptedDocObj();
		if (ObjStmMark != null)
		{
			foreach (var entry in ObjStmMark)
			{
				var n = entry.Key;
				var h = entry.Value;
				ReadObjStm((PrStream)_xrefObj[n], h);
				_xrefObj[n] = null;
			}

			ObjStmMark = null;
		}

		Xref = null;
	}

	private void readDecryptedDocObj()
	{
		if (Encrypted)
		{
			return;
		}

		var encDic = trailer?.Get(PdfName.Encrypt);
		if (encDic == null || encDic.ToString().Equals("null", StringComparison.Ordinal))
		{
			return;
		}

		//_encryptionError = true;
		baseType.GetField("_encryptionError", BindingFlags.NonPublic | BindingFlags.Instance).SetValue(this, true);

		byte[] encryptionKey = null;

		Encrypted = true;
		var enc = (PdfDictionary)GetPdfObject(encDic);

		string s;
		PdfObject o;

		var documentIDs = trailer.GetAsArray(PdfName.Id);
		byte[] documentId = null;
		if (documentIDs != null)
		{
			o = documentIDs[0];
			Strings.Remove((PdfString)o);
			s = o.ToString();
			documentId = DocWriter.GetIsoBytes(s);
			if (documentIDs.Size > 1)
			{
				Strings.Remove((PdfString)documentIDs[1]);
			}
		}

		// just in case we have a broken producer
		if (documentId == null)
		{
			documentId = Array.Empty<byte>();
		}

		byte[] uValue = null;
		byte[] oValue = null;
		var cryptoMode = PdfWriter.STANDARD_ENCRYPTION_40;
		var lengthValue = 0;

		var filter = GetPdfObjectRelease(enc.Get(PdfName.Filter));

		if (filter.Equals(PdfName.Standard))
		{
			s = enc.Get(PdfName.U).ToString();
			Strings.Remove((PdfString)enc.Get(PdfName.U));
			uValue = DocWriter.GetIsoBytes(s);
			s = enc.Get(PdfName.O).ToString();
			Strings.Remove((PdfString)enc.Get(PdfName.O));
			oValue = DocWriter.GetIsoBytes(s);

			o = enc.Get(PdfName.P);
			if (!o.IsNumber())
			{
				throw new InvalidPdfException($"Illegal P = {o} value.");
			}

			PValue = ((PdfNumber)o).IntValue;

			o = enc.Get(PdfName.R);
			if (!o.IsNumber())
			{
				throw new InvalidPdfException($"Illegal R = {o} value.");
			}

			RValue = ((PdfNumber)o).IntValue;

			switch (RValue)
			{
				case 2:
					cryptoMode = PdfWriter.STANDARD_ENCRYPTION_40;
					break;
				case 3:
					o = enc.Get(PdfName.LENGTH);
					if (!o.IsNumber())
					{
						throw new InvalidPdfException("Illegal Length value.");
					}

					lengthValue = ((PdfNumber)o).IntValue;
					if (lengthValue > 128 || lengthValue < 40 || lengthValue % 8 != 0)
					{
						throw new InvalidPdfException("Illegal Length value.");
					}

					cryptoMode = PdfWriter.STANDARD_ENCRYPTION_128;
					break;
				case 4:
					var dic = (PdfDictionary)enc.Get(PdfName.Cf);
					if (dic == null)
					{
						throw new InvalidPdfException("/CF not found (encryption)");
					}

					dic = (PdfDictionary)dic.Get(PdfName.Stdcf);
					if (dic == null)
					{
						throw new InvalidPdfException("/StdCF not found (encryption)");
					}

					if (PdfName.V2.Equals(dic.Get(PdfName.Cfm)))
					{
						cryptoMode = PdfWriter.STANDARD_ENCRYPTION_128;
					}
					else if (PdfName.Aesv2.Equals(dic.Get(PdfName.Cfm)))
					{
						cryptoMode = PdfWriter.ENCRYPTION_AES_128;
					}
					else
					{
						throw new UnsupportedPdfException("No compatible encryption found");
					}

					var em = enc.Get(PdfName.Encryptmetadata);
					if (em != null && em.ToString().Equals("false", StringComparison.Ordinal))
					{
						cryptoMode |= PdfWriter.DO_NOT_ENCRYPT_METADATA;
					}

					break;
				case 6:
					cryptoMode = PdfWriter.ENCRYPTION_AES_256_V3;
					em = enc.Get(PdfName.Encryptmetadata);
					if (em != null && em.ToString().Equals("false", StringComparison.Ordinal))
					{
						cryptoMode |= PdfWriter.DO_NOT_ENCRYPT_METADATA;
					}

					break;
				default:
					throw new UnsupportedPdfException("Unknown encryption type R = " + RValue);
			}
		}
		else if (filter.Equals(PdfName.Pubsec))
		{
			var foundRecipient = false;
			byte[] envelopedData = null;
			PdfArray recipients = null;

			o = enc.Get(PdfName.V);
			if (!o.IsNumber())
			{
				throw new InvalidPdfException("Illegal V value.");
			}

			var vValue = ((PdfNumber)o).IntValue;
			switch (vValue)
			{
				case 1:
					cryptoMode = PdfWriter.STANDARD_ENCRYPTION_40;
					lengthValue = 40;
					recipients = (PdfArray)enc.Get(PdfName.Recipients);
					break;
				case 2:
					o = enc.Get(PdfName.LENGTH);
					if (!o.IsNumber())
					{
						throw new InvalidPdfException("Illegal Length value.");
					}

					lengthValue = ((PdfNumber)o).IntValue;
					if (lengthValue > 128 || lengthValue < 40 || lengthValue % 8 != 0)
					{
						throw new InvalidPdfException("Illegal Length value.");
					}

					cryptoMode = PdfWriter.STANDARD_ENCRYPTION_128;
					recipients = (PdfArray)enc.Get(PdfName.Recipients);
					break;
				case 4:
					var dic = (PdfDictionary)enc.Get(PdfName.Cf);
					if (dic == null)
					{
						throw new InvalidPdfException("/CF not found (encryption)");
					}

					dic = (PdfDictionary)dic.Get(PdfName.Defaultcryptfilter);
					if (dic == null)
					{
						throw new InvalidPdfException("/DefaultCryptFilter not found (encryption)");
					}

					if (PdfName.V2.Equals(dic.Get(PdfName.Cfm)))
					{
						cryptoMode = PdfWriter.STANDARD_ENCRYPTION_128;
						lengthValue = 128;
					}
					else if (PdfName.Aesv2.Equals(dic.Get(PdfName.Cfm)))
					{
						cryptoMode = PdfWriter.ENCRYPTION_AES_128;
						lengthValue = 128;
					}
					else
					{
						throw new UnsupportedPdfException("No compatible encryption found");
					}

					var em = dic.Get(PdfName.Encryptmetadata);
					if (em != null && em.ToString().Equals("false", StringComparison.Ordinal))
					{
						cryptoMode |= PdfWriter.DO_NOT_ENCRYPT_METADATA;
					}

					recipients = (PdfArray)dic.Get(PdfName.Recipients);
					break;
				default:
					throw new UnsupportedPdfException("Unknown encryption type V = " + RValue);
			}

			for (var i = 0; i < recipients.Size; i++)
			{
				var recipient = recipients[i];
				Strings.Remove((PdfString)recipient);

				CmsEnvelopedData data = null;
				data = new CmsEnvelopedData(recipient.GetBytes());

				foreach (var recipientInfo in data.GetRecipientInfos().GetRecipients())
				{
					if (recipientInfo.RecipientID.Match(Certificate) && !foundRecipient)
					{
						envelopedData = recipientInfo.GetContent(CertificateKey);
						foundRecipient = true;
					}
				}
			}

			if (!foundRecipient || envelopedData == null)
			{
				throw new UnsupportedPdfException("Bad certificate and key.");
			}

#if NET462
			using (var sh = new SHA1CryptoServiceProvider())
			{
				sh.TransformBlock(envelopedData, 0, 20, envelopedData, 0);
				for (var i = 0; i < recipients.Size; i++)
				{
					var encodedRecipient = recipients[i].GetBytes();
					sh.TransformBlock(encodedRecipient, 0, encodedRecipient.Length, encodedRecipient, 0);
				}

				if ((cryptoMode & PdfWriter.DO_NOT_ENCRYPT_METADATA) != 0)
				{
					sh.TransformBlock(PdfEncryptionInternal.MetadataPad, 0, PdfEncryptionInternal.MetadataPad.Length,
									  PdfEncryptionInternal.MetadataPad, 0);
				}

				sh.TransformFinalBlock(envelopedData, 0, 0);
				encryptionKey = sh.Hash;
			}
#else
			using (var sh = IncrementalHash.CreateHash(HashAlgorithmName.SHA1))
			{
				sh.AppendData(envelopedData, 0, 20);
				for (var i = 0; i < recipients.Size; i++)
				{
					var encodedRecipient = recipients[i].GetBytes();
					sh.AppendData(encodedRecipient, 0, encodedRecipient.Length);
				}

				if ((cryptoMode & PdfWriter.DO_NOT_ENCRYPT_METADATA) != 0)
				{
					sh.AppendData(PdfEncryptionInternal.MetadataPad, 0, PdfEncryptionInternal.MetadataPad.Length);
				}

				encryptionKey = sh.GetHashAndReset();
			}
#endif
		}

		bool _ownerPasswordUsed = false;
		var decrypt = new PdfEncryptionInternal();
		this.decrypt = decrypt;
		decrypt.SetCryptoMode(cryptoMode, lengthValue);

		if (filter.Equals(PdfName.Standard))
		{
			if (RValue < 6)
			{
				//check by owner password
				decrypt.SetupByOwnerPassword(documentId, Password, uValue, oValue, PValue);
				if (!equalsArray(uValue, decrypt.UserKey, RValue == 3 || RValue == 4 ? 16 : 32))
				{
					//check by user password
					decrypt.SetupByUserPassword(documentId, Password, oValue, PValue);
					if (!equalsArray(uValue, decrypt.UserKey, RValue == 3 || RValue == 4 ? 16 : 32))
					{
						int pValue = PValue;
						int rValue = RValue;
						throw new BadPasswordExceptionTriable("Bad user password", p =>
						{
							var decrypt = new PdfEncryptionInternal();
							decrypt.SetCryptoMode(cryptoMode, lengthValue);
							decrypt.SetupByOwnerPassword(documentId, p, uValue, oValue, pValue);
							if (equalsArray(uValue, decrypt.UserKey, rValue == 3 || rValue == 4 ? 16 : 32)) return BadPasswordExceptionTriable.TryPasswordResult.SuccessOwnerPassword;
							decrypt.SetupByUserPassword(documentId, p, oValue, pValue);
							if (equalsArray(uValue, decrypt.UserKey, rValue == 3 || rValue == 4 ? 16 : 32)) return BadPasswordExceptionTriable.TryPasswordResult.SuccessUserPassword;
							return BadPasswordExceptionTriable.TryPasswordResult.Fail;
						});
					}
				}
				else
				{
					_ownerPasswordUsed = true;
				}
			}
			else
			{
				// implements Algorithm 2.A: Retrieving the file encryption key from an encrypted document in order to decrypt it (revision 6 and later) - ISO 32000-2 section 7.6.4.3.3
				s = enc.Get(PdfName.UE).ToString();
				Strings.Remove((PdfString)enc.Get(PdfName.UE));
				var ueValue = DocWriter.GetIsoBytes(s);
				s = enc.Get(PdfName.OE).ToString();
				Strings.Remove((PdfString)enc.Get(PdfName.OE));
				var oeValue = DocWriter.GetIsoBytes(s);
				s = enc.Get(PdfName.Perms).ToString();
				Strings.Remove((PdfString)enc.Get(PdfName.Perms));
				var permsValue = DocWriter.GetIsoBytes(s);

				// step b of Algorithm 2.A
				var password = Password;
				if (password == null)
				{
					password = Array.Empty<byte>();
				}
				else if (password.Length > 127)
				{
					password = password.CopyOf(127);
				}

				// According to ISO 32000-2 the uValue is expected to be 48 bytes in length.
				// Actual documents from the wild tend to have the uValue filled with zeroes
				// to a 127 bytes length. As input to computeHash for owner password related
				// operations, though, we must only use the 48 bytes.
				if (uValue != null && uValue.Length > 48)
				{
					uValue = uValue.CopyOf(48);
				}

				// step c of Algorithm 2.A
				var hashAlg2B = PdfEncryption.HashAlg2B(password, oValue.CopyOfRange(32, 40), uValue);
				if (equalsArray(hashAlg2B, oValue, 32))
				{
					// step d of Algorithm 2.A
					decrypt.SetupByOwnerPassword(documentId, password, uValue, ueValue, oValue, oeValue, PValue);
					// step f of Algorithm 2.A
					if (decrypt.DecryptAndCheckPerms(permsValue))
					{
						_ownerPasswordUsed = true;
					}
				}

				if (!_ownerPasswordUsed)
				{
					int pValue = this.PValue;
					Func<byte[], BadPasswordExceptionTriable.TryPasswordResult> passwordTester = p =>
					{
						var decrypt = new PdfEncryption();
						decrypt.SetCryptoMode(cryptoMode, lengthValue);
						var password = p;
						if (password == null)
						{
							password = Array.Empty<byte>();
						}
						else if (password.Length > 127)
						{
							password = password.CopyOf(127);
						}
						var hashAlg2B = PdfEncryption.HashAlg2B(password, oValue.CopyOfRange(32, 40), uValue);
						if (equalsArray(hashAlg2B, oValue, 32))
						{
							// step d of Algorithm 2.A
							decrypt.SetupByOwnerPassword(documentId, password, uValue, ueValue, oValue, oeValue, pValue);
							// step f of Algorithm 2.A
							if (decrypt.DecryptAndCheckPerms(permsValue))
							{
								return BadPasswordExceptionTriable.TryPasswordResult.SuccessOwnerPassword;
							}
						}
						hashAlg2B = PdfEncryption.HashAlg2B(password, uValue.CopyOfRange(32, 40), null);
						if (!equalsArray(hashAlg2B, uValue, 32)) return BadPasswordExceptionTriable.TryPasswordResult.Fail;
						decrypt.SetupByUserPassword(documentId, password, uValue, ueValue, oValue, oeValue, pValue);
						if (!decrypt.DecryptAndCheckPerms(permsValue)) return BadPasswordExceptionTriable.TryPasswordResult.Fail;
						return BadPasswordExceptionTriable.TryPasswordResult.SuccessUserPassword;
					};

					// analog of step c of Algorithm 2.A for user password
					hashAlg2B = PdfEncryption.HashAlg2B(password, uValue.CopyOfRange(32, 40), null);
					if (!equalsArray(hashAlg2B, uValue, 32))
					{
						throw new BadPasswordExceptionTriable("Bad user password", passwordTester);
					}

					// step e of Algorithm 2.A
					decrypt.SetupByUserPassword(documentId, password, uValue, ueValue, oValue, oeValue, PValue);
					// step f of Algorithm 2.A
					if (!decrypt.DecryptAndCheckPerms(permsValue))
					{
						throw new BadPasswordExceptionTriable("Bad user password", passwordTester);
					}
				}

				PValue = decrypt.Permissions;
			}
		}
		else if (filter.Equals(PdfName.Pubsec))
		{
			decrypt.SetupByEncryptionKey(encryptionKey, lengthValue);
			_ownerPasswordUsed = true;
		}

		for (var k = 0; k < Strings.Count; ++k)
		{
			var str = Strings[k];
			typeof(PdfString).GetMethod("Decrypt", BindingFlags.NonPublic | BindingFlags.Instance)?.Invoke(str, new[] { this });
			//str.Decrypt(this);
		}

		if (encDic.IsIndirect())
		{
			baseType.GetField("_cryptoRef", BindingFlags.NonPublic | BindingFlags.Instance).SetValue(this, (PrIndirectReference)encDic);
			//_cryptoRef = (PrIndirectReference)encDic;
			var _cryptoRef = (PrIndirectReference)encDic;
			var _xrefObj = (List<PdfObject>)baseType.GetField("_xrefObj", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(this);
			_xrefObj[_cryptoRef.Number] = null;
		}

		//_encryptionError = false;
		baseType.GetField("_ownerPasswordUsed", BindingFlags.NonPublic | BindingFlags.Instance).SetValue(this, _ownerPasswordUsed);
		baseType.GetField("_encryptionError", BindingFlags.NonPublic | BindingFlags.Instance).SetValue(this, false);
	}

	private static bool equalsArray(byte[] ar1, byte[] ar2, int size)
	{
		for (var k = 0; k < size; ++k)
		{
			if (ar1[k] != ar2[k])
			{
				return false;
			}
		}

		return true;
	}

}
