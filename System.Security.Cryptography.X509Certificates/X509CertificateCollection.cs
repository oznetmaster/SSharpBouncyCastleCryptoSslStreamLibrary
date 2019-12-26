//
// System.Security.Cryptography.X509Certificates.X509CertificateCollection
//
// Authors:
//	Lawrence Pit (loz@cable.a2000.nl)
//	Sebastien Pouliot (spouliot@motus.com)
//
// Copyright (C) 2004 Novell (http://www.novell.com)
//

//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System;
using System.Collections;
using System.Globalization;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
#if SSHARP
using Crestron.SimplSharp.Cryptography;
using BCX509Certificate = Org.BouncyCastle.X509.X509Certificate;
using BCX509Certificate2 = Org.BouncyCastle.X509.X509Certificate;
#else
using System.Security.Cryptography;
#endif

#if SSHARP
namespace Crestron.SimplSharp.Cryptography.X509Certificates
#else
namespace System.Security.Cryptography.X509Certificates
#endif
	{
	[Serializable]
	public class BCX509CertificateCollection : CollectionBase
		{
		public BCX509CertificateCollection ()
			{
			}

		public BCX509CertificateCollection (BCX509Certificate[] value)
			{
			AddRange (value);
			}

		public BCX509CertificateCollection (BCX509CertificateCollection value)
			{
			AddRange (value);
			}

		public BCX509CertificateCollection (X509Certificate[] value)
			{
			AddRange (value);
			}

		public BCX509CertificateCollection (X509CertificateCollection value)
			{
			AddRange (value);
			}

		// Properties

		public BCX509Certificate this [int index]
			{
			get { return (BCX509Certificate)InnerList[index]; }
			set { InnerList[index] = value; }
			}

		// Methods

		public int Add (BCX509Certificate value)
			{
			if (value == null)
				throw new ArgumentNullException ("value");

			return InnerList.Add (value);
			}

		public void AddRange (BCX509Certificate[] value)
			{
			if (value == null)
				throw new ArgumentNullException ("value");

			for (int i = 0; i < value.Length; i++)
				InnerList.Add (value[i]);
			}

		public void AddRange (BCX509CertificateCollection value)
			{
			if (value == null)
				throw new ArgumentNullException ("value");

			for (int i = 0; i < value.InnerList.Count; i++)
				InnerList.Add (value[i]);
			}

		public void AddRange (X509Certificate[] value)
			{
			if (value == null)
				throw new ArgumentNullException ("value");

			for (int i = 0; i < value.Length; i++)
				InnerList.Add (DotNetUtilities.FromX509Certificate (value[i]));
			}

		public void AddRange (X509CertificateCollection value)
			{
			if (value == null)
				throw new ArgumentNullException ("value");

			for (int i = 0; i < value.Count; i++)
				InnerList.Add (DotNetUtilities.FromX509Certificate (value[i]));
			}

		public bool Contains (BCX509Certificate value)
			{
			if (value == null)
				return false;

			byte[] hash = value.GetSignature ();
			for (int i = 0; i < InnerList.Count; i++)
				{
				BCX509Certificate x509 = (BCX509Certificate)InnerList[i];
				if (Compare (x509.GetSignature(), hash))
					return true;
				}
			return false;
			}

		public void CopyTo (BCX509Certificate[] array, int index)
			{
			InnerList.CopyTo (array, index);
			}

		public new BCX509CertificateEnumerator GetEnumerator ()
			{
			return new BCX509CertificateEnumerator (this);
			}

		public override int GetHashCode ()
			{
			return InnerList.GetHashCode ();
			}

		public int IndexOf (BCX509Certificate value)
			{
			return InnerList.IndexOf (value);
			}

		public void Insert (int index, BCX509Certificate value)
			{
			InnerList.Insert (index, value);
			}

		public void Remove (BCX509Certificate value)
			{
			if (value == null)
				throw new ArgumentNullException ("value");
			if (IndexOf (value) == -1)
				throw new ArgumentException ("value", "Not part of the collection.");

			InnerList.Remove (value);
			}

		// private stuff

		private bool Compare (byte[] array1, byte[] array2)
			{
			if ((array1 == null) && (array2 == null))
				return true;
			if ((array1 == null) || (array2 == null))
				return false;
			if (array1.Length != array2.Length)
				return false;
			for (int i = 0; i < array1.Length; i++)
				{
				if (array1[i] != array2[i])
					return false;
				}
			return true;
			}

		public BCX509CertificateCollection Find (BCX509FindType findType, object findValue, bool validOnly)
			{
			if (findValue == null)
				throw new ArgumentNullException ("findValue");

			string str = String.Empty;
			DerObjectIdentifier oid = null;
			string oidStr = String.Empty;
			KeyUsage ku = new KeyUsage(0);
			DateTime dt = DateTime.MinValue;

			switch (findType)
				{
				case BCX509FindType.FindByThumbprint:
				case BCX509FindType.FindBySubjectName:
				case BCX509FindType.FindBySubjectDistinguishedName:
				case BCX509FindType.FindByIssuerName:
				case BCX509FindType.FindByIssuerDistinguishedName:
				case BCX509FindType.FindBySerialNumber:
				case BCX509FindType.FindByTemplateName:
				case BCX509FindType.FindBySubjectKeyIdentifier:
					try
						{
						str = (string)findValue;
						}
					catch (Exception e)
						{
						string msg = String.Format("Invalid find value type '{0}', expected '{1}'.", findValue.GetType (), "string");
						throw new CryptographicException (msg, e);
						}
					break;
				case BCX509FindType.FindByApplicationPolicy:
				case BCX509FindType.FindByCertificatePolicy:
				case BCX509FindType.FindByExtension:
					try
						{
						oidStr = (string)findValue;
						}
					catch (Exception e)
						{
						string msg = String.Format("Invalid find value type '{0}', expected '{1}'.", findValue.GetType (), "X509KeyUsageFlags");
						throw new CryptographicException (msg, e);
						}
					// OID validation
					try
						{
						oid = new DerObjectIdentifier (oidStr);
						}
					catch (FormatException)
						{
						string msg = String.Format ("Invalid OID value '{0}'.", oidStr);
						throw new ArgumentException ("findValue", msg);
						}
					break;
				case BCX509FindType.FindByKeyUsage:
					try
						{
						ku = new KeyUsage((int)findValue);
						}
					catch (Exception e)
						{
						string msg = String.Format ("Invalid find value type '{0}', expected '{1}'.", findValue.GetType (), "X509KeyUsageFlags");
						throw new CryptographicException (msg, e);
						}
					break;
				case BCX509FindType.FindByTimeValid:
				case BCX509FindType.FindByTimeNotYetValid:
				case BCX509FindType.FindByTimeExpired:
					try
						{
						dt = (DateTime)findValue;
						}
					catch (Exception e)
						{
						string msg = String.Format ("Invalid find value type '{0}', expected '{1}'.", findValue.GetType (), "X509DateTime");
						throw new CryptographicException (msg, e);
						}
					break;
				default:
						{
						string msg = String.Format ("Invalid find type '{0}'.", findType);
						throw new CryptographicException (msg);
						}
				}

			CultureInfo cinv = CultureInfo.InvariantCulture;
			BCX509CertificateCollection results = new BCX509CertificateCollection ();
			foreach (BCX509Certificate2 x in InnerList)
				{
				bool value_match = false;

				switch (findType)
					{
					case BCX509FindType.FindByThumbprint:
						// works with Thumbprint, GetCertHashString in both normal (upper) and lower case
						value_match = ((String.Compare (str, Hex.ToHexString (x.GetSignature ()), true, cinv) == 0) || (String.Compare (str, DotNetUtilities.ToX509Certificate (x).GetCertHashString (), true, cinv) == 0));
						break;
					case BCX509FindType.FindBySubjectName:
						{
						string[] names = x.SubjectDN.ToString().Split (new []{','}, StringSplitOptions.RemoveEmptyEntries);
						foreach (string name in names)
							{
							int pos = name.IndexOf ('=');
							value_match = (name.IndexOf (str, pos, StringComparison.InvariantCultureIgnoreCase) >= 0);
							if (value_match)
								break;
							}
						break;
						}
					case BCX509FindType.FindBySubjectDistinguishedName:
						value_match = (String.Compare (str, x.SubjectDN.ToString(), true, cinv) == 0);
						break;
					case BCX509FindType.FindByIssuerName:
						{
						//string iname = x.GetNameInfo (X509NameType.SimpleName, true);
						//value_match = (iname.IndexOf (str, StringComparison.InvariantCultureIgnoreCase) >= 0);
						string[] names = x.IssuerDN.ToString().Split (new []{','}, StringSplitOptions.RemoveEmptyEntries);
						foreach (string name in names)
							{
							int pos = name.IndexOf ('=');
							value_match = (name.IndexOf (str, pos, StringComparison.InvariantCultureIgnoreCase) >= 0);
							if (value_match)
								break;
							}
						}
						break;
					case BCX509FindType.FindByIssuerDistinguishedName:
						value_match = (String.Compare (str, x.IssuerDN.ToString(), true, cinv) == 0);
						break;
					case BCX509FindType.FindBySerialNumber:
						value_match = (String.Compare (str, x.SerialNumber.ToString(), true, cinv) == 0);
						break;
					case BCX509FindType.FindByTemplateName:
						// TODO - find a valid test case
						break;
					case BCX509FindType.FindBySubjectKeyIdentifier:
						SubjectKeyIdentifier ski = SubjectKeyIdentifier.GetInstance(x.CertificateStructure.TbsCertificate.Extensions.GetExtension (X509Extensions.SubjectKeyIdentifier));
						if (ski != null)
							value_match = (String.Compare (str, Hex.ToHexString(ski.GetKeyIdentifier ()), true, cinv) == 0);
						break;
					case BCX509FindType.FindByApplicationPolicy:
						// note: include when no extensions are present (even if v3)
						value_match = (x.GetCriticalExtensionOids ().Count == 0 && x.GetNonCriticalExtensionOids ().Count == 0);
						// TODO - find test case with extension
						break;
					case BCX509FindType.FindByCertificatePolicy:
						// TODO - find test case with extension
						break;
					case BCX509FindType.FindByExtension:
						value_match = (x.GetExtensionValue (oid) != null);
						break;
					case BCX509FindType.FindByKeyUsage:
						KeyUsage kue = KeyUsage.GetInstance(x.CertificateStructure.TbsCertificate.Extensions.GetExtension(X509Extensions.KeyUsage));
						if (kue == null)
							{
							// key doesn't have any hard coded limitations
							// note: MS doesn't check for ExtendedKeyUsage
							value_match = true;
							}
						else
							value_match = ((kue.IntValue & ku.IntValue) == ku.IntValue);
						break;
					case BCX509FindType.FindByTimeValid:
						value_match = ((dt >= x.NotBefore) && (dt <= x.NotAfter));
						break;
					case BCX509FindType.FindByTimeNotYetValid:
						value_match = (dt < x.NotBefore);
						break;
					case BCX509FindType.FindByTimeExpired:
						value_match = (dt > x.NotAfter);
						break;
					}

				if (!value_match)
					continue;

				if (validOnly)
					{
					try
						{
						x.Verify (x.GetPublicKey ());
						results.Add (x);
						}
					catch
						{
						}
					}
				else
					results.Add (x);
				}
			return results;
			}

		// Inner Class

		public class BCX509CertificateEnumerator : IEnumerator
			{
			private IEnumerator enumerator;

			// Constructors

			public BCX509CertificateEnumerator (BCX509CertificateCollection mappings)
				{
				enumerator = ((IEnumerable)mappings).GetEnumerator ();
				}

			// Properties

			public BCX509Certificate Current
				{
				get { return (BCX509Certificate)enumerator.Current; }
				}

			object IEnumerator.Current
				{
				get { return enumerator.Current; }
				}

			// Methods

			bool IEnumerator.MoveNext ()
				{
				return enumerator.MoveNext ();
				}

			void IEnumerator.Reset ()
				{
				enumerator.Reset ();
				}

			public bool MoveNext ()
				{
				return enumerator.MoveNext ();
				}

			public void Reset ()
				{
				enumerator.Reset ();
				}
			}
		}
	}