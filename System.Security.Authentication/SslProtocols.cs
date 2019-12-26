using System;

namespace Crestron.SimplSharp.Security.Authentication
	{
	[Flags]
	public enum SslProtocols
		{
		None = 0,
		Ssl2 = 12,
		Ssl3 = 48,
		Tls = 192,
		Tls11 = 768,
		Tls12 = 3072,
		Tls13 = 12288,
		Default = Ssl3 | Tls
		}
	}

