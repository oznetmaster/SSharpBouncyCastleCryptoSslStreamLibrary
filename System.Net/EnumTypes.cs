#region Copyright and License
// -----------------------------------------------------------------------------------------------------------------
// 
// EnumTypes.cs
// 
// Copyright © 2019 Nivloc Enterprises Ltd.  All rights reserved.
// 
// -----------------------------------------------------------------------------------------------------------------
// 
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//  
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//  
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
// 
// 
// 
#endregion
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Crestron.SimplSharp;

namespace Crestron.SimplSharp.Net
	{
	[Flags]
	internal enum SchProtocols
		{
		Zero = 0,
		PctClient = 0x00000002,
		PctServer = 0x00000001,
		Pct = (PctClient | PctServer),
		Ssl2Client = 0x00000008,
		Ssl2Server = 0x00000004,
		Ssl2 = (Ssl2Client | Ssl2Server),
		Ssl3Client = 0x00000020,
		Ssl3Server = 0x00000010,
		Ssl3 = (Ssl3Client | Ssl3Server),
		Tls10Client = 0x00000080,
		Tls10Server = 0x00000040,
		Tls10 = (Tls10Client | Tls10Server),
		Tls11Client = 0x00000200,
		Tls11Server = 0x00000100,
		Tls11 = (Tls11Client | Tls11Server),
		Tls12Client = 0x00000800,
		Tls12Server = 0x00000400,
		Tls12 = (Tls12Client | Tls12Server),
		Tls13Client = 0x00002000,
		Tls13Server = 0x00001000,
		Tls13 = (Tls13Client | Tls13Server),
		Ssl3Tls = (Ssl3 | Tls10),
		UniClient = unchecked ((int)0x80000000),
		UniServer = 0x40000000,
		Unified = (UniClient | UniServer),
		ClientMask = (PctClient | Ssl2Client | Ssl3Client | Tls10Client | Tls11Client | Tls12Client | Tls13Client | UniClient),
		ServerMask = (PctServer | Ssl2Server | Ssl3Server | Tls10Server | Tls11Server | Tls12Server | Tls13Server | UniServer)
		};

	[Flags]
	internal enum Alg
		{
		Any = 0,
		ClassSignture = (1 << 13),
		ClassEncrypt = (3 << 13),
		ClassHash = (4 << 13),
		ClassKeyXch = (5 << 13),
		TypeRSA = (2 << 9),
		TypeBlock = (3 << 9),
		TypeStream = (4 << 9),
		TypeDH = (5 << 9),
		TypeSRP = (6 << 9),

		NameDES = 1,
		NameRC2 = 2,
		Name3DES = 3,
		NameAES_128 = 14,
		NameAES_192 = 15,
		NameAES_256 = 16,
		NameAES = 17,
		NameIDEA = 20,
		NameSEED = 21,
		NameCamellia_128 = 24,
		NameCamellia_256 = 25,
		NameCamellia = 26,

		NameRC4 = 1,
		NameChaCha20_Poly1305 = 2,

		NameMD5 = 3,
		NameSHA = 4,
		NameSHA256 = 12,
		NameSHA384 = 13,
		NameSHA512 = 14,

		NameDH_Ephem = 2,
		}
	}
