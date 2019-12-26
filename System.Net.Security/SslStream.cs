#region Copyright and License
// -----------------------------------------------------------------------------------------------------------------
// 
// SslStream.cs
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
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using Crestron.SimplSharp;
using Crestron.SimplSharp.CrestronIO;
using Crestron.SimplSharp.Cryptography.X509Certificates;
using Crestron.SimplSharp.Security.Authentication;
using Cresttron.SimplSharp.Net.Security;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Security;
using BCX = Org.BouncyCastle.X509;
using AsyncCallback = Crestron.SimplSharp.CrestronIO.AsyncCallback;
using IAsyncResult = Crestron.SimplSharp.CrestronIO.IAsyncResult;
using SSMono.Threading;

namespace Crestron.SimplSharp.Net.Security
	{
	public class SslStream : Stream
		{
		internal TlsClientProtocol TlsClientProtocol;
		internal TlsServerProtocol TlsServerProtocol;
		internal Stream InnerStream;
		internal bool LeaveInnerStreamOpen;
		internal RemoteCertificateValidationCallback RemoteCertificateValidationCallback;
		internal LocalCertificateSelectionCallback LocalCertificateSelectionCallback;
		internal EncryptionPolicy EncryptionPolicy;
		internal SecureRandom SecureRandom;
		internal Stream SecureStream;
		internal string TargetHost;
		internal X509CertificateCollection ClientCertificates;
		internal X509Certificate ServerCertificate;
		internal X509Certificate ClientCertificate;
		private bool _disposed;
		private bool _authenticationAttempted;
		private SslStreamTlsClient _sslStreamClient;
		private SslStreamTlsServer _sslStreamServer;

		public SslStream (Stream innerStream)
			: this (innerStream, false, null, null, EncryptionPolicy.RequireEncryption)
			{
			}

		public SslStream (Stream innerStream, bool leaveInnerStreamOpen)
			: this (innerStream, leaveInnerStreamOpen, null, null, EncryptionPolicy.RequireEncryption)
			{
			}

		public SslStream (Stream innerStream, bool leaveInnerStreamOpen, RemoteCertificateValidationCallback userCertificateValidationCallback)
			: this (innerStream, leaveInnerStreamOpen, userCertificateValidationCallback, null, EncryptionPolicy.RequireEncryption)
			{
			}

		public SslStream (
			Stream innerStream, bool leaveInnerStreamOpen, RemoteCertificateValidationCallback userCertificateValidationCallback,
			LocalCertificateSelectionCallback userCertificateSelectionCallback)
			: this (innerStream, leaveInnerStreamOpen, userCertificateValidationCallback, userCertificateSelectionCallback, EncryptionPolicy.RequireEncryption)
			{
			}

		public SslStream (
			Stream innerStream, bool leaveInnerStreamOpen, RemoteCertificateValidationCallback userCertificateValidationCallback,
			LocalCertificateSelectionCallback userCertificateSelectionCallback, EncryptionPolicy encryptionPolicy)
			{
			InnerStream = innerStream;
			LeaveInnerStreamOpen = leaveInnerStreamOpen;
			RemoteCertificateValidationCallback = userCertificateValidationCallback;
			LocalCertificateSelectionCallback = userCertificateSelectionCallback;
			EncryptionPolicy = encryptionPolicy;
			SslProtocol = SslProtocols.None;
			IsAuthenticated = false;

			if (InnerStream == null || InnerStream == Null)
				throw new ArgumentNullException ("innerStream");

			if (!InnerStream.CanRead || !InnerStream.CanWrite)
				throw new ArgumentException ("must be both readbale and writable", "innerStream");

			if (EncryptionPolicy < EncryptionPolicy.RequireEncryption || EncryptionPolicy > EncryptionPolicy.NoEncryption)
				throw new ArgumentException ("invalid policy", "encryptionPolicy");
			}

		public virtual void AuthenticateAsClient (string targetHost)
			{
			AuthenticateAsClient (targetHost, null, SslProtocols.None, false);
			}

		public virtual void AuthenticateAsClient (string targetHost, X509CertificateCollection clientCertificates, bool checkCertificateRevocation)
			{
			AuthenticateAsClient (targetHost, clientCertificates, SslProtocols.None, checkCertificateRevocation);
			}

		public virtual void AuthenticateAsClient (
			string targetHost, X509CertificateCollection clientCertificates, SslProtocols enabledSslProtocols, bool checkCertificateRevocation)
			{
			if (targetHost == null)
				throw new ArgumentNullException ("targetHost");
			if (!Enum.IsDefined (typeof(SslProtocols), enabledSslProtocols))
				throw new ArgumentException ("invalid value", "enabledSslProtocols");
			if (_disposed)
				throw new ObjectDisposedException ("SslStream");
			if (IsAuthenticated)
				throw new InvalidOperationException ("Already authenticated");
			if (_authenticationAttempted)
				throw new InvalidOperationException ("Authentication already failed");

			TargetHost = targetHost;
			ClientCertificates = clientCertificates;
			SecureRandom = new SecureRandom ();
			TlsClientProtocol = new TlsClientProtocol (InnerStream, SecureRandom);
			_authenticationAttempted = true;
			_sslStreamClient = new SslStreamTlsClient (this);
			try
				{
				TlsClientProtocol.Connect (_sslStreamClient);
				}
			catch (Exception ex)
				{
				if (ex is AuthenticationException)
					throw;

				throw new AuthenticationException ("Authentication failure", ex);
				}
			SecureStream = TlsClientProtocol.Stream;
			IsServer = false;
			IsAuthenticated = true;
			}

		public virtual IAsyncResult BeginAuthenticateAsClient (string targetHost, AsyncCallback asyncCallback, object asyncState)
			{
			return BeginAuthenticateAsClient (targetHost, null, SslProtocols.None, false, asyncCallback, asyncState);
			}

		public virtual IAsyncResult BeginAuthenticateAsClient (
			string targetHost, X509CertificateCollection clientCertificates, bool checkCertificateRevocation, AsyncCallback asyncCallback, object asyncState)
			{
			return BeginAuthenticateAsClient (targetHost, clientCertificates, SslProtocols.None, checkCertificateRevocation, asyncCallback, asyncState);
			}

		public virtual IAsyncResult BeginAuthenticateAsClient (
			string targetHost, X509CertificateCollection clientCertificates, SslProtocols enabledSslProtocols, bool checkCertificateRevocation,
			AsyncCallback asyncCallback, object asyncState)
			{
			if (targetHost == null)
				throw new ArgumentNullException ("targetHost");
			if (!Enum.IsDefined (typeof(SslProtocols), enabledSslProtocols))
				throw new ArgumentException ("invalid value", "enabledSslProtocols");
			if (_disposed)
				throw new ObjectDisposedException ("SslStream");
			if (IsAuthenticated)
				throw new InvalidOperationException ("Already authenticated");
			if (_authenticationAttempted)
				throw new InvalidOperationException ("Authentication already failed");

			TargetHost = targetHost;
			ClientCertificates = clientCertificates;
			SecureRandom = new SecureRandom ();
			TlsClientProtocol = new TlsClientProtocol (InnerStream, SecureRandom);
			var iar = new AuthenticateAsClientAsyncResult (asyncState);
			_sslStreamClient = new SslStreamTlsClient (this);
			_authenticationAttempted = true;
			ThreadPool.QueueUserWorkItem (state =>
				{
				var tup = (Tuple<AuthenticateAsClientAsyncResult, AsyncCallback>)state;
				var ir = tup.Item1;
				var cb = tup.Item2;
				try
					{
					TlsClientProtocol.Connect (_sslStreamClient);
					SecureStream = TlsClientProtocol.Stream;
					IsServer = false;
					IsAuthenticated = true;
					}
				catch (Exception ex)
					{
					if (ex is AuthenticationException)
						ir.Exception = ex;
					else
						ir.Exception = new AuthenticationException ("Authentication failure", ex);
					}

				ir.IsCompleted = true;
				ir.AsyncWaitHandle.Set ();

				if (cb != null)
					cb (ir);
				}, Tuple.Create (iar, asyncCallback));

			return iar;
			}

		public virtual void EndAuthenticateAsClient (IAsyncResult asyncResult)
			{
			var iar = asyncResult as AuthenticateAsClientAsyncResult;
			if (iar == null)
				throw new ArgumentException ("Invalid asyncResult", "asyncResult");

			iar.AsyncWaitHandle.Wait ();

			if (iar.Exception != null)
				throw iar.Exception;
			}

		private class AuthenticateAsClientAsyncResult : IAsyncResult
			{
			public AuthenticateAsClientAsyncResult (object state)
				{
				AsyncState = state;

				AsyncWaitHandle = new ManualResetEvent (false);
				}

			public Exception Exception { get; internal set; }

			#region IAsyncResult Members

			public object AsyncState { get; private set; }

			public CEventHandle AsyncWaitHandle { get; private set; }

			public bool CompletedSynchronously { get; internal set; }

			public object InnerObject
				{
				get { throw new NotImplementedException (); }
				}

			public bool IsCompleted { get; internal set; }

			#endregion
			}

		public virtual void AuthenticateAsServer (X509Certificate serverCertificate)
			{
			AuthenticateAsServer (serverCertificate, false, SslProtocols.None, false, null);
			}

		public virtual void AuthenticateAsServer (X509Certificate serverCertificate, bool clientCertificateRequired, bool checkCertificateRevocation)
			{
			AuthenticateAsServer (serverCertificate, clientCertificateRequired, SslProtocols.None, checkCertificateRevocation, null);
			}

		public virtual void AuthenticateAsServer (
			X509Certificate serverCertificate, bool clientCertificateRequired, SslProtocols enabledSslProtocols, bool checkCertificateRevocation)
			{
			AuthenticateAsServer (serverCertificate, clientCertificateRequired, enabledSslProtocols, checkCertificateRevocation, null);
			}

		public virtual void AuthenticateAsServer (
			X509Certificate serverCertificate, bool clientCertificateRequired, SslProtocols enabledSslProtocols, bool checkCertificateRevocation, byte[] privateKey)
			{
			if (serverCertificate == null)
				throw new ArgumentNullException ("serverCertificate");
			if (!Enum.IsDefined (typeof(SslProtocols), enabledSslProtocols))
				throw new ArgumentException ("invalid value", "enabledSslProtocols");
			if (_disposed)
				throw new ObjectDisposedException ("SslStream");
			if (IsAuthenticated)
				throw new InvalidOperationException ("Already authenticated");
			if (_authenticationAttempted)
				throw new InvalidOperationException ("Authentication already failed");

			ServerCertificate = serverCertificate;
			SecureRandom = new SecureRandom ();
			TlsServerProtocol = new TlsServerProtocol (InnerStream, SecureRandom);
			_authenticationAttempted = true;
			try
				{
				_sslStreamServer = new SslStreamTlsServer (this, DotNetUtilities.FromX509Certificate (ServerCertificate),
					privateKey == null ? null : PrivateKeyFactory.CreateKey (privateKey));
				TlsServerProtocol.Accept (_sslStreamServer);
				}
			catch (Exception ex)
				{
				if (ex is AuthenticationException)
					throw;

				throw new AuthenticationException ("Authentication failure", ex);
				}

			SecureStream = TlsServerProtocol.Stream;
			LocalCertificate = serverCertificate;
			IsServer = true;
			IsAuthenticated = true;
			}

		public virtual void AuthenticateAsServer (BCX.X509Certificate serverCertificate)
			{
			AuthenticateAsServer (serverCertificate, false, SslProtocols.None, false, null);
			}

		public virtual void AuthenticateAsServer (BCX.X509Certificate serverCertificate, bool clientCertificateRequired, bool checkCertificateRevocation)
			{
			AuthenticateAsServer (serverCertificate, clientCertificateRequired, SslProtocols.None, checkCertificateRevocation, null);
			}

		public virtual void AuthenticateAsServer (
			BCX.X509Certificate serverCertificate, bool clientCertificateRequired, SslProtocols enabledSslProtocols, bool checkCertificateRevocation)
			{
			AuthenticateAsServer (serverCertificate, clientCertificateRequired, enabledSslProtocols, checkCertificateRevocation, null);
			}

		public virtual void AuthenticateAsServer (
			BCX.X509Certificate serverCertificate, bool clientCertificateRequired, SslProtocols enabledSslProtocols, bool checkCertificateRevocation,
			AsymmetricKeyParameter privateKey)
			{
			if (serverCertificate == null)
				throw new ArgumentNullException ("serverCertificate");
			if (!Enum.IsDefined (typeof(SslProtocols), enabledSslProtocols))
				throw new ArgumentException ("invalid value", "enabledSslProtocols");
			if (_disposed)
				throw new ObjectDisposedException ("SslStream");
			if (IsAuthenticated)
				throw new InvalidOperationException ("Already authenticated");
			if (_authenticationAttempted)
				throw new InvalidOperationException ("Authentication already failed");

			ServerCertificate = serverCertificate;
			SecureRandom = new SecureRandom ();
			TlsServerProtocol = new TlsServerProtocol (InnerStream, SecureRandom);
			_authenticationAttempted = true;
			try
				{
				_sslStreamServer = new SslStreamTlsServer (this, serverCertificate, privateKey);
				TlsServerProtocol.Accept (_sslStreamServer);
				}
			catch (Exception ex)
				{
				if (ex is AuthenticationException)
					throw;

				throw new AuthenticationException ("Authentication failure", ex);
				}

			SecureStream = TlsServerProtocol.Stream;
			LocalCertificate = ServerCertificate;
			IsServer = true;
			IsAuthenticated = true;
			}

		public virtual IAsyncResult BeginAuthenticateAsServer (X509Certificate serverCertificate, AsyncCallback asyncCallback, object asyncState)
			{
			return BeginAuthenticateAsServer (serverCertificate, false, SslProtocols.None, false, null, asyncCallback, asyncState);
			}

		public virtual IAsyncResult BeginAuthenticateAsServer (
			X509Certificate serverCertificate, bool clientCertificateRequired, bool checkCertificateRevocation, AsyncCallback asyncCallback, object asyncState)
			{
			return BeginAuthenticateAsServer (serverCertificate, clientCertificateRequired, SslProtocols.None, checkCertificateRevocation, null, asyncCallback,
				asyncState);
			}

		public virtual IAsyncResult BeginAuthenticateAsServer (
			X509Certificate serverCertificate, bool clientCertificateRequired, SslProtocols enabledSslProtocols, bool checkCertificateRevocation,
			AsyncCallback asyncCallback, object asyncState)
			{
			return BeginAuthenticateAsServer (serverCertificate, clientCertificateRequired, enabledSslProtocols, checkCertificateRevocation, null, asyncCallback,
				asyncState);
			}

		public virtual IAsyncResult BeginAuthenticateAsServer (
			X509Certificate serverCertificate, bool clientCertificateRequired, SslProtocols enabledSslProtocols, bool checkCertificateRevocation, byte[] privateKey,
			AsyncCallback asyncCallback, object asyncState)
			{
			if (serverCertificate == null)
				throw new ArgumentNullException ("serverCertificate");
			if (!Enum.IsDefined (typeof(SslProtocols), enabledSslProtocols))
				throw new ArgumentException ("invalid value", "enabledSslProtocols");
			if (_disposed)
				throw new ObjectDisposedException ("SslStream");
			if (IsAuthenticated)
				throw new InvalidOperationException ("Already authenticated");
			if (_authenticationAttempted)
				throw new InvalidOperationException ("Authentication already failed");

			ServerCertificate = serverCertificate;
			SecureRandom = new SecureRandom ();
			TlsServerProtocol = new TlsServerProtocol (InnerStream, SecureRandom);
			var iar = new AuthenticateAsServerAsyncResult (asyncState);
			_authenticationAttempted = true;
			ThreadPool.QueueUserWorkItem (state =>
				{
				var tup = (Tuple<AuthenticateAsServerAsyncResult, AsyncCallback>)state;
				var ir = tup.Item1;
				var cb = tup.Item2;
				try
					{
					_sslStreamServer = new SslStreamTlsServer (this, DotNetUtilities.FromX509Certificate (ServerCertificate),
						privateKey == null ? null : PrivateKeyFactory.CreateKey (privateKey));
					TlsServerProtocol.Accept (_sslStreamServer);
					SecureStream = TlsServerProtocol.Stream;
					LocalCertificate = serverCertificate;
					IsServer = true;
					IsAuthenticated = true;
					}
				catch (Exception ex)
					{
					if (ex is AuthenticationException)
						ir.Exception = ex;
					else
						ir.Exception = new AuthenticationException ("Authentication failure", ex);
					}

				ir.IsCompleted = true;
				ir.AsyncWaitHandle.Set ();

				if (cb != null)
					cb (ir);
				}, Tuple.Create (iar, asyncCallback));

			return iar;
			}

		public virtual IAsyncResult BeginAuthenticateAsServer (BCX.X509Certificate serverCertificate, AsyncCallback asyncCallback, object asyncState)
			{
			return BeginAuthenticateAsServer (serverCertificate, false, SslProtocols.None, false, null, asyncCallback, asyncState);
			}

		public virtual IAsyncResult BeginAuthenticateAsServer (
			BCX.X509Certificate serverCertificate, bool clientCertificateRequired, bool checkCertificateRevocation, AsyncCallback asyncCallback, object asyncState)
			{
			return BeginAuthenticateAsServer (serverCertificate, clientCertificateRequired, SslProtocols.None, checkCertificateRevocation, null, asyncCallback,
				asyncState);
			}

		public virtual IAsyncResult BeginAuthenticateAsServer (
			BCX.X509Certificate serverCertificate, bool clientCertificateRequired, SslProtocols enabledSslProtocols, bool checkCertificateRevocation,
			AsyncCallback asyncCallback, object asyncState)
			{
			return BeginAuthenticateAsServer (serverCertificate, clientCertificateRequired, enabledSslProtocols, checkCertificateRevocation, null, asyncCallback,
				asyncState);
			}

		public virtual IAsyncResult BeginAuthenticateAsServer (
			BCX.X509Certificate serverCertificate, bool clientCertificateRequired, SslProtocols enabledSslProtocols, bool checkCertificateRevocation,
			AsymmetricKeyParameter privateKey, AsyncCallback asyncCallback, object asyncState)
			{
			if (serverCertificate == null)
				throw new ArgumentNullException ("serverCertificate");
			if (!Enum.IsDefined (typeof(SslProtocols), enabledSslProtocols))
				throw new ArgumentException ("invalid value", "enabledSslProtocols");
			if (_disposed)
				throw new ObjectDisposedException ("SslStream");
			if (IsAuthenticated)
				throw new InvalidOperationException ("Already authenticated");
			if (_authenticationAttempted)
				throw new InvalidOperationException ("Authentication already failed");

			ServerCertificate = serverCertificate;
			SecureRandom = new SecureRandom ();
			TlsServerProtocol = new TlsServerProtocol (InnerStream, SecureRandom);
			var iar = new AuthenticateAsServerAsyncResult (asyncState);
			_authenticationAttempted = true;
			ThreadPool.QueueUserWorkItem (state =>
				{
				var tup = (Tuple<AuthenticateAsServerAsyncResult, AsyncCallback>)state;
				var ir = tup.Item1;
				var cb = tup.Item2;
				try
					{
					_sslStreamServer = new SslStreamTlsServer (this, serverCertificate, privateKey);
					TlsServerProtocol.Accept (_sslStreamServer);
					SecureStream = TlsServerProtocol.Stream;
					LocalCertificate = serverCertificate;
					IsServer = true;
					IsAuthenticated = true;
					}
				catch (Exception ex)
					{
					if (ex is AuthenticationException)
						ir.Exception = ex;
					else
						ir.Exception = new AuthenticationException ("Authentication failure", ex);
					}

				ir.IsCompleted = true;
				ir.AsyncWaitHandle.Set ();

				if (cb != null)
					cb (ir);
				}, Tuple.Create (iar, asyncCallback));

			return iar;
			}

		public virtual void EndAuthenticateAsServer (IAsyncResult asyncResult)
			{
			var iar = asyncResult as AuthenticateAsServerAsyncResult;
			if (iar == null)
				throw new ArgumentException ("Invalid asyncResult", "asyncResult");

			iar.AsyncWaitHandle.Wait ();

			if (iar.Exception != null)
				throw iar.Exception;
			}

		private class AuthenticateAsServerAsyncResult : IAsyncResult
			{
			public AuthenticateAsServerAsyncResult (object state)
				{
				AsyncState = state;

				AsyncWaitHandle = new ManualResetEvent (false);
				}

			public Exception Exception { get; internal set; }

			#region IAsyncResult Members

			public object AsyncState { get; private set; }

			public CEventHandle AsyncWaitHandle { get; private set; }

			public bool CompletedSynchronously { get; internal set; }

			public object InnerObject
				{
				get { throw new NotImplementedException (); }
				}

			public bool IsCompleted { get; internal set; }

			#endregion
			}

		public X509Certificate RemoteCertificate { get; internal set; }

		public X509Certificate LocalCertificate { get; internal set; }

		public bool IsAuthenticated { get; private set; }

		public SslProtocols SslProtocol { get; internal set; }

		public bool IsServer { get; private set; }

		public bool IsEncrypted
			{
			get { return IsAuthenticated; }
			}

		public bool IsMutuallyAuthenticated
			{
			get { return IsAuthenticated && (IsServer ? RemoteCertificate != null : LocalCertificate != null); }
			}

		public bool IsSigned
			{
			get { return IsAuthenticated; }
			}

		public int BouncyNegotiatedCipherSuite
			{
			get { return IsServer ? _sslStreamServer.SelectedCipherSuite : _sslStreamClient.SelectedCipherSuite; }
			}

		public int BouncyCipherAlgorithm
			{
			get { return TlsUtilities.GetEncryptionAlgorithm (BouncyNegotiatedCipherSuite); }
			}

		public CipherAlgorithmType CipherAlgorithm
			{
			get
				{
				switch (BouncyCipherAlgorithm)
					{
					case EncryptionAlgorithm.NULL: //0;
						return CipherAlgorithmType.Null;
					case EncryptionAlgorithm.RC4_40: //1;
					case EncryptionAlgorithm.RC4_128: //2;
						return CipherAlgorithmType.Rc4;
					case EncryptionAlgorithm.RC2_CBC_40: //3;
						return CipherAlgorithmType.Rc2;
					case EncryptionAlgorithm.IDEA_CBC: //4;
						return CipherAlgorithmType.Idea;
					case EncryptionAlgorithm.DES40_CBC: //5;
					case EncryptionAlgorithm.DES_CBC: //6;
						return CipherAlgorithmType.Des;
					case EncryptionAlgorithm.cls_3DES_EDE_CBC: //7;
						return CipherAlgorithmType.TripleDes;
						/*
         * RFC 3268
         */
					case EncryptionAlgorithm.AES_128_CBC: //8;
						return CipherAlgorithmType.Aes128;
					case EncryptionAlgorithm.AES_256_CBC: //9;
						return CipherAlgorithmType.Aes256;

						/*
         * RFC 5289
         */
					case EncryptionAlgorithm.AES_128_GCM: //10;
						return CipherAlgorithmType.Aes128;
					case EncryptionAlgorithm.AES_256_GCM: //11;
						return CipherAlgorithmType.Aes256;

						/*
         * RFC 4132
         */
					case EncryptionAlgorithm.CAMELLIA_128_CBC: //12;
						return CipherAlgorithmType.Camellia128;
					case EncryptionAlgorithm.CAMELLIA_256_CBC: //13;
						return CipherAlgorithmType.Camellia256;

						/*
         * RFC 4162
         */
					case EncryptionAlgorithm.SEED_CBC: //14;
						return CipherAlgorithmType.Seed;
						/*
         * RFC 6655
         */
					case EncryptionAlgorithm.AES_128_CCM: //15;
					case EncryptionAlgorithm.AES_128_CCM_8: //16;
						return CipherAlgorithmType.Aes128;
					case EncryptionAlgorithm.AES_256_CCM: //17;
					case EncryptionAlgorithm.AES_256_CCM_8: //18;
						return CipherAlgorithmType.Aes256;
						/*
         * RFC 6367
         */
					case EncryptionAlgorithm.CAMELLIA_128_GCM: //19;
						return CipherAlgorithmType.Camellia128;
					case EncryptionAlgorithm.CAMELLIA_256_GCM: //20;
						return CipherAlgorithmType.Camellia256;
						/*
         * RFC 7905
         */
					case EncryptionAlgorithm.CHACHA20_POLY1305: //21;
						return CipherAlgorithmType.ChaCha20Poly1305;

						/*
         * draft-zauner-tls-aes-ocb-04
         */
					case EncryptionAlgorithm.AES_128_OCB_TAGLEN96: //103;
						return CipherAlgorithmType.Aes128;
					case EncryptionAlgorithm.AES_256_OCB_TAGLEN96: //104;
						return CipherAlgorithmType.Aes256;

					default:
						throw new InvalidOperationException ("unknown encryption algorithm");
					}
				}
			}

		public int CipherStrength
			{
			get
				{
				if (!IsAuthenticated)
					return 0;

				switch (BouncyCipherAlgorithm)
					{
					case EncryptionAlgorithm.NULL: //0;
						return 0;
					case EncryptionAlgorithm.RC4_40: //1;
						return 40;
					case EncryptionAlgorithm.RC4_128: //2;
						return 128;
					case EncryptionAlgorithm.RC2_CBC_40: //3;
						return 40;
					case EncryptionAlgorithm.IDEA_CBC: //4;
						return 128;
					case EncryptionAlgorithm.DES40_CBC: //5;
						return 40;
					case EncryptionAlgorithm.DES_CBC: //6;
						return 56;
					case EncryptionAlgorithm.cls_3DES_EDE_CBC: //7;
						return 168;
						/*
         * RFC 3268
         */
					case EncryptionAlgorithm.AES_128_CBC: //8;
						return 128;
					case EncryptionAlgorithm.AES_256_CBC: //9;
						return 256;

						/*
         * RFC 5289
         */
					case EncryptionAlgorithm.AES_128_GCM: //10;
						return 128;
					case EncryptionAlgorithm.AES_256_GCM: //11;
						return 256;

						/*
         * RFC 4132
         */
					case EncryptionAlgorithm.CAMELLIA_128_CBC: //12;
						return 128;
					case EncryptionAlgorithm.CAMELLIA_256_CBC: //13;
						return 256;

						/*
         * RFC 4162
         */
					case EncryptionAlgorithm.SEED_CBC: //14;
						return 128;
						/*
         * RFC 6655
         */
					case EncryptionAlgorithm.AES_128_CCM: //15;
					case EncryptionAlgorithm.AES_128_CCM_8: //16;
						return 128;
					case EncryptionAlgorithm.AES_256_CCM: //17;
					case EncryptionAlgorithm.AES_256_CCM_8: //18;
						return 256;
						/*
         * RFC 6367
         */
					case EncryptionAlgorithm.CAMELLIA_128_GCM: //19;
						return 128;
					case EncryptionAlgorithm.CAMELLIA_256_GCM: //20;
						return 256;
						/*
         * RFC 7905
         */
					case EncryptionAlgorithm.CHACHA20_POLY1305: //21;
						return 256;

						/*
         * draft-zauner-tls-aes-ocb-04
         */
					case EncryptionAlgorithm.AES_128_OCB_TAGLEN96: //103;
						return 128;
					case EncryptionAlgorithm.AES_256_OCB_TAGLEN96: //104;
						return 256;

					default:
						throw new InvalidOperationException ("unknown encryption algorithm");
					}
				}
			}

		public int BouncyKeyExchangeAlgorithm
			{
			get { return TlsUtilities.GetKeyExchangeAlgorithm (BouncyNegotiatedCipherSuite); }
			}

		public ExchangeAlgorithmType KeyExchangeAlgorithm
			{
			get
				{
				switch (BouncyKeyExchangeAlgorithm)
					{
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.NULL: //0;
						return ExchangeAlgorithmType.None;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.RSA: //1;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.RSA_EXPORT: //2;
						return ExchangeAlgorithmType.RsaKeyX;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DHE_DSS: //3;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DHE_DSS_EXPORT: //4;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DHE_RSA: //5;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DHE_RSA_EXPORT: //6;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DH_DSS: //7;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DH_DSS_EXPORT: //8;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DH_RSA: //9;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DH_RSA_EXPORT: //10;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DH_anon: //11;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DH_anon_EXPORT: //12;
						return ExchangeAlgorithmType.DiffieHellman;

						/*
         * RFC 4279
         */
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.PSK: //13;
						return ExchangeAlgorithmType.RsaKeyX;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DHE_PSK: //14;
						return ExchangeAlgorithmType.DiffieHellman;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.RSA_PSK: //15;
						return ExchangeAlgorithmType.RsaKeyX;

						/*
         * RFC 4429
         */
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.ECDH_ECDSA: //16;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.ECDHE_ECDSA: //17;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.ECDH_RSA: //18;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.ECDHE_RSA: //19;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.ECDH_anon: //20;
						return ExchangeAlgorithmType.DiffieHellman;

						/*
         * RFC 5054
         */
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.SRP: //21;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.SRP_DSS: //22;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.SRP_RSA: //23;
						return ExchangeAlgorithmType.SecureRemotePassword;

						/*
         * RFC 5489
         */
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.ECDHE_PSK: //24;
						return ExchangeAlgorithmType.DiffieHellman;

					default:
						throw new InvalidOperationException ("unknown key exchange algorithm");
					}
				}
			}

		public int KeyExchangeStrength
			{
			get
				{
				if (!IsAuthenticated)
					return 0;

				switch (BouncyKeyExchangeAlgorithm)
					{
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.NULL: //0;
						return 0;

					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.RSA: //1;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.RSA_EXPORT: //2;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DHE_DSS: //3;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DHE_DSS_EXPORT: //4;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DHE_RSA: //5;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DHE_RSA_EXPORT: //6;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DH_DSS: //7;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DH_DSS_EXPORT: //8;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DH_RSA: //9;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DH_RSA_EXPORT: //10;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DH_anon: //11;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DH_anon_EXPORT: //12;

						/*
         * RFC 4279
         */
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.PSK: //13;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.DHE_PSK: //14;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.RSA_PSK: //15;

						/*
         * RFC 4429
         */
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.ECDH_ECDSA: //16;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.ECDHE_ECDSA: //17;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.ECDH_RSA: //18;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.ECDHE_RSA: //19;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.ECDH_anon: //20;

						/*
         * RFC 5054
         */
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.SRP: //21;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.SRP_DSS: //22;
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.SRP_RSA: //23;

						/*
         * RFC 5489
         */
					case Org.BouncyCastle.Crypto.Tls.KeyExchangeAlgorithm.ECDHE_PSK: //24;

						/**/
						return 0;

					default:
						throw new InvalidOperationException ("unknown key exchange algorithm");
					}
				}
			}

		public int BounchHashAlgorithm
			{
			get { return TlsUtilities.GetMacAlgorithm (BouncyNegotiatedCipherSuite); }
			}

		public HashAlgorithmType HashAlgorithm
			{
			get
				{
				switch (BounchHashAlgorithm)
					{
					case MacAlgorithm.cls_null: //0;
						return HashAlgorithmType.None;
					case MacAlgorithm.md5: //1;
						return HashAlgorithmType.Md5;
					case MacAlgorithm.sha: //2;
						return HashAlgorithmType.Sha1;

						/*
         * RFC 5246
         */
					case MacAlgorithm.hmac_sha256: //3;
						return HashAlgorithmType.Sha256;
					case MacAlgorithm.hmac_sha384: //4;
						return HashAlgorithmType.Sha384;
					case MacAlgorithm.hmac_sha512: //5;
						return HashAlgorithmType.Sha512;

					default:
						throw new InvalidOperationException ("unknown hash algorithm"); 
					}
				}
			}

		public int HashStrength
			{
			get
				{
				if (!IsAuthenticated)
					return 0;

				switch (HashAlgorithm)
					{
					case HashAlgorithmType.None:
						return 0;
					case HashAlgorithmType.Sha1:
						return 160;
					case HashAlgorithmType.Md5:
						return 128;
					case HashAlgorithmType.Sha256:
						return 256;
					case HashAlgorithmType.Sha384:
						return 384;
					case HashAlgorithmType.Sha512:
						return 512;
					default:
						throw new InvalidOperationException ("unknown has algorithm");
					}
				}
			}

		public override bool CanRead
			{
			get { return SecureStream != null && SecureStream.CanRead; }
			}

		public override bool CanSeek
			{
			get { return false; }
			}

		public override bool CanWrite
			{
			get { return SecureStream != null && SecureStream.CanWrite; }
			}

		public override void Flush ()
			{
			SecureStream.Flush ();
			}

		public override long Length
			{
			get { return SecureStream.Length; }
			}

		public override long Position
			{
			get { return SecureStream.Position; }
			set { throw new NotSupportedException (); }
			}

		public override int Read (byte[] buffer, int offset, int count)
			{
			return SecureStream.Read (buffer, offset, count);
			}

		public override int ReadByte ()
			{
			return SecureStream.ReadByte ();
			}

		public override IAsyncResult BeginRead (byte[] buffer, int offset, int count, AsyncCallback callback, object state)
			{
			return SecureStream.BeginRead (buffer, offset, count, callback, state);
			}

		public override int EndRead (IAsyncResult asyncResult)
			{
			return SecureStream.EndRead (asyncResult);
			}

		public override long Seek (long offset, SeekOrigin origin)
			{
			throw new NotSupportedException ();
			}

		public override void SetLength (long value)
			{
			SecureStream.SetLength (value);
			}

		public override void Write (byte[] buffer, int offset, int count)
			{
			SecureStream.Write (buffer, offset, count);
			}

		public void Write (byte[] buffer)
			{
			Write (buffer, 0, buffer.Length);
			}

		public override void WriteByte (byte value)
			{
			SecureStream.WriteByte (value);
			}

		public override IAsyncResult BeginWrite (byte[] buffer, int offset, int count, AsyncCallback callback, object state)
			{
			return SecureStream.BeginWrite (buffer, offset, count, callback, state);
			}

		public override void EndWrite (IAsyncResult asyncResult)
			{
			SecureStream.EndWrite (asyncResult);
			}

		protected override void Dispose (bool disposing)
			{
			if (!disposing || _disposed)
				return;

			_disposed = true;

			if (SecureStream != null)
				{
				SecureStream.Close ();
				SecureStream = null;
				}

			if (!LeaveInnerStreamOpen)
				InnerStream.Close ();
			}
		}

	internal class SslStreamTlsClient : DefaultTlsClient
		{
		private readonly SslStream _sslStream;

		public int SelectedCipherSuite
			{
			get
				{
				if (!_sslStream.IsAuthenticated)
					throw new InvalidOperationException ("Ssl stream has not been authenticated");

				return mSelectedCipherSuite;
				}
			}

		public SslStreamTlsClient (SslStream sslStream)
			{
			_sslStream = sslStream;
			}

		public override TlsAuthentication GetAuthentication ()
			{
			return new SslStreamTlsAuthentication (_sslStream);
			}
		}

	internal class SslStreamTlsAuthentication : TlsAuthentication
		{
		private readonly SslStream _sslStream;

		public SslStreamTlsAuthentication (SslStream sslStream)
			{
			_sslStream = sslStream;
			}

		#region TlsAuthentication Members

		public TlsCredentials GetClientCredentials (CertificateRequest certificateRequest)
			{
			if (_sslStream.LocalCertificateSelectionCallback == null)
				return null;

			var cert = _sslStream.LocalCertificateSelectionCallback (_sslStream, _sslStream.TargetHost, _sslStream.ClientCertificates, _sslStream.ServerCertificate,
				certificateRequest.CertificateAuthorities.Cast<X509Name> ().Select (xn => xn.ToString ()).ToArray ());

			_sslStream.LocalCertificate = cert;

			if (cert == null)
				return null;

			return new DefaultTlsAgreementCredentials (new Certificate (new[] {DotNetUtilities.FromX509Certificate (cert).CertificateStructure}),
				(AsymmetricKeyParameter)certificateRequest.SupportedSignatureAlgorithms[0]);
			}

		public void NotifyServerCertificate (Certificate serverCertificate)
			{
			_sslStream.ServerCertificate = DotNetUtilities.ToX509Certificate (serverCertificate.GetCertificateAt (0));

			if (_sslStream.RemoteCertificateValidationCallback == null)
				return;

			var chain = new X509Chain ();
			chain.ChainElements.Add (serverCertificate.GetCertificateList ().Select (cert => new BCX.X509Certificate (cert)));

			var remoteCertificate = DotNetUtilities.ToX509Certificate (serverCertificate.GetCertificateAt (0));
			if (!_sslStream.RemoteCertificateValidationCallback (_sslStream, remoteCertificate, chain, SslPolicyErrors.None))
				throw new AuthenticationException ("The authentication failed and left this object in an unusable state");

			_sslStream.RemoteCertificate = remoteCertificate;
			}

		#endregion
		}

	internal class SslStreamTlsServer : DefaultTlsServer
		{
		private readonly SslStream _sslStream;
		private readonly BCX.X509Certificate _serverCertificate;
		private readonly AsymmetricKeyParameter _privateKey;

		public int SelectedCipherSuite
			{
			get
				{
				if (!_sslStream.IsAuthenticated)
					throw new InvalidOperationException ("Ssl stream has not been authenticated");

				return mSelectedCipherSuite;
				}
			}

		public SslStreamTlsServer (SslStream sslStream, BCX.X509Certificate serverCertificate)
			: this (sslStream, serverCertificate, null)
			{
			}

		public SslStreamTlsServer (SslStream sslStream, BCX.X509Certificate serverCertificate, AsymmetricKeyParameter privateKey)
			{
			_sslStream = sslStream;
			_serverCertificate = serverCertificate;
			_privateKey = privateKey ?? _serverCertificate.GetPublicKey ();
			}

		public override void NotifyClientCertificate (Certificate clientCertificate)
			{
			_sslStream.ClientCertificate = DotNetUtilities.ToX509Certificate (clientCertificate.GetCertificateAt (0));

			if (_sslStream.RemoteCertificateValidationCallback == null)
				return;

			var chain = new X509Chain ();
			chain.ChainElements.Add (clientCertificate.GetCertificateList ().Select (cert => new BCX.X509Certificate (cert)));

			var remoteCertificate = DotNetUtilities.ToX509Certificate (clientCertificate.GetCertificateAt (0));
			if (!_sslStream.RemoteCertificateValidationCallback (_sslStream, remoteCertificate, chain, SslPolicyErrors.None))
				throw new AuthenticationException ("The authentication failed and left this object in an unusable state");

			_sslStream.RemoteCertificate = remoteCertificate;
			}

		protected override TlsSignerCredentials GetRsaSignerCredentials ()
			{
			return new DefaultTlsSignerCredentials (mContext, new Certificate (new[] {_serverCertificate.CertificateStructure}), _privateKey);
			}
		}
	}
