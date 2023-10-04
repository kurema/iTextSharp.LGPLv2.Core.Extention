using System;
using System.Collections.Generic;
using System.Text;

namespace iTextSharp.text.pdf;

public class BadPasswordExceptionTriable : BadPasswordException
{
	public BadPasswordExceptionTriable(Func<byte[], TryPasswordResult> tester) : base()
	{
		this.Tester = tester;
	}
	public BadPasswordExceptionTriable(string message, Func<byte[], TryPasswordResult> tester) : base(message)
	{
		this.Tester = tester;
	}
	public BadPasswordExceptionTriable(string message, Exception innerException, Func<byte[], TryPasswordResult> tester) : base(message, innerException)
	{
		this.Tester = tester;
	}
	public TryPasswordResult? TryPassword(byte[] password)
	{
		if (Tester is null) return null;
		return Tester.Invoke(password);
	}
	public bool CanTryPassword => Tester is not null;
	internal Func<byte[], TryPasswordResult> Tester { get; }
	public enum TryPasswordResult
	{
		SuccessOwnerPassword, SuccessUserPassword, Fail,
	}

	public static bool IsSucess(TryPasswordResult? arg) => arg switch { TryPasswordResult.SuccessOwnerPassword or TryPasswordResult.SuccessUserPassword => true, _ => false };
}
