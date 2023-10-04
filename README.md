# iTextSharp.LGPLv2.Core.Extention
Tiny fix to iTextSharp.LGPLv2.Core

DO NOT USE!

This is a simple inherited class of PdfReader of [iTextSharp.LGPLv2.Core](https://github.com/VahidN/iTextSharp.LGPLv2.Core) that allows efficient password lookup.
It basically do what [PR #128 of original repo](https://github.com/VahidN/iTextSharp.LGPLv2.Core/pull/128) do.
I recommend you to use this only to try various password if you do.

## Sample
```cs
using iTextSharp.text.pdf;

try
{
	using var reader = new PdfReaderTriable(inputFile);
}
catch (BadPasswordExceptionTriable pe)
{
	if (pe.CanTryPassword)
	{
		string correctPassword = null;
		foreach (var candidate in new string[] { "password", "owner" })
		{
			switch (pe.TryPassword(Encoding.UTF8.GetBytes(candidate)))
			{
				case BadPasswordExceptionTriable.TryPasswordResult.SuccessOwnerPassword:
				case BadPasswordExceptionTriable.TryPasswordResult.SuccessUserPassword:
					correctPassword = candidate;
					break;
			}
			if (correctPassword is not null) break;
		}
		//Do something.
	}
}
```

## Limitation
This library 
* heavily rely on behavior of the original library. Future update may brake something.
* uses Reflection to access private fields or methods.

This library is specifically designed to be used in [BookViewer 3](https://github.com/kurema/BookViewerApp3).
Only reason this is separate repository is that the original library is LGPL. I want BookViewer 3 to be MIT licensed.

## Note
Date: 2023/10/05 (Y/M/D)

[History of original PdfReader](https://github.com/VahidN/iTextSharp.LGPLv2.Core/commits/master/src/iTextSharp.LGPLv2.Core/iTextSharp/text/pdf/PdfReader.cs).
