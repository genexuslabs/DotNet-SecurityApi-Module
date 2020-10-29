using SecurityAPICommons.Commons;
using SecurityAPICommons.Utils;
using Renci.SshNet;
using Renci.SshNet.Common;
using Sftp.GeneXusCommons;
using Sftp.GeneXusSftpUtils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;


namespace Sftp.GeneXusSftp
{
    [SecuritySafeCritical]
    public class SftpClient : ISftpClientObject
    {

        private Renci.SshNet.SftpClient channel;
        private static KnownHostStore _knownHosts;
        private bool fingerprint;
        private ExtensionsWhiteList whiteList;


        [SecuritySafeCritical]
        public SftpClient() : base()
        {

            this.channel = null;
            this.fingerprint = false;
            this.whiteList = null;


        }

        /******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/
        [SecuritySafeCritical]
        public override bool Connect(SftpOptions options)
        {
            if (options.HasError())
            {
                this.error = options.GetError();
                return false;
            }
            bool useKey = false;
            if (SecurityUtils.compareStrings("", options.KeyPath) || SecurityUtils.compareStrings("", options.User) || SecurityUtils.compareStrings("", options.KeyPassword))
            {
                useKey = false;
                if (SecurityUtils.compareStrings("", options.User)
                        || SecurityUtils.compareStrings("", options.Password))
                {

                    this.error.setError("SF001", "Authentication misconfiguration");
                    return false;
                }
                else
                {
                    useKey = false;
                }
            }
            else
            {
                useKey = true;
            }



            if (SecurityUtils.compareStrings("", options.Host))
            {
                this.error.setError("SF003", "Empty host");
                return false;
            }
            try
            {

                SetupChannelSftp(options, useKey);
                if (this.channel == null)
                {
                    return false;
                }

                if (!this.channel.IsConnected)
                {
                    this.channel.Connect();
                }



            }
            catch (Exception e)
            {
                this.error.setError("SF004", e.Message);
                return false;
            }


            this.whiteList = options.WhiteList;
            return true;

        }

        [SecuritySafeCritical]
        public override bool Put(String localPath, String remoteDir)
        {
            if (this.whiteList != null)
            {
                if (!this.whiteList.IsValid(localPath))
                {
                    this.error.setError("WL001", "Invalid file extension");
                    return false;
                }
            }
            if (SecurityUtils.compareStrings("", localPath) || localPath == null || localPath.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
            {
                this.error.setError("SF0012", "localPath cannot be empty");
                return false;
            }
            if (remoteDir.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
            {
                this.error.setError("SF015", "Invalid remoteDir");
                return false;
            }
            string local_path = localPath;
            //var local_path = $"/{localPath.Replace(@"\", "/")}";
            if (this.channel == null || !this.channel.IsConnected)
            {
                this.error.setError("SF005", "The channel is invalid, reconect");
                return false;
            }

            FileStream stream = null;
            try
            {
                stream = File.OpenRead(local_path);
            }
            catch (Exception e)
            {
                this.error.setError("SF011", e.Message);
                return false;
            }

            string rDir = "";
            bool control = false;
			try
			{
                control = this.channel.WorkingDirectory.Contains("/");

            }catch(Exception e)
			{
                this.error.setError("SF018", e.Message);
                return false;
			}
            if (control)
            {
                remoteDir = $"/{remoteDir.Replace(@"\", "/")}";
                rDir += this.channel.WorkingDirectory + remoteDir + "/" + GetFileNamne(localPath);
            }
            else
            {
                rDir = this.channel.WorkingDirectory + remoteDir + "\\" + GetFileNamne(localPath);
            }
            try
            {
                this.channel.UploadFile(stream, rDir, true, null);
            }
            catch (Exception e)
            {
                this.error.setError("SF012", e.Message);

                return false;
            }

            return true;

        }

        [SecuritySafeCritical]
        public override bool Get(String remoteFilePath, String localDir)
        {
            if (this.whiteList != null)
            {
                if (!this.whiteList.IsValid(remoteFilePath))
                {
                    this.error.setError("WL002", "Invalid file extension");
                    return false;
                }
            }
            if (SecurityUtils.compareStrings("", remoteFilePath) || remoteFilePath == null || remoteFilePath.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
            {
                this.error.setError("SF013", "remoteFilePath cannot be empty");
                return false;
            }
            if (localDir.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
            {
                this.error.setError("SF014", "Invalid localDir");
                return false;
            }

            if (this.channel == null || !this.channel.IsConnected)
            {
                this.error.setError("SF007", "The channel is invalid, reconect");
                return false;
            }
            string rDir = "";
            if (this.channel.WorkingDirectory.Contains("/"))
            {
                remoteFilePath = $"/{remoteFilePath.Replace(@"\", "/")}";

                rDir += this.channel.WorkingDirectory + remoteFilePath;
            }
            else
            {

                rDir = this.channel.WorkingDirectory + remoteFilePath;
            }
            try
            {


                Stream file = new FileStream(localDir + GetFileNamne(remoteFilePath), FileMode.Create);
                this.channel.DownloadFile(rDir, file);


            }
            catch (Exception e)
            {
                this.error.setError("SF008", e.Message);
                return false;
            }
            return true;
        }

        [SecuritySafeCritical]
        public override void Disconnect()
        {
            if (this.channel != null && this.channel.IsConnected)
            {
                this.channel.Disconnect();
            }
        }

        [SecuritySafeCritical]
        public override string GetWorkingDirectory()
        {
            if (this.channel != null && this.channel.IsConnected)
            {
                try
                {
                    return this.channel.WorkingDirectory;
                }
                catch (Exception)
                {
                    this.error.setError("SF017", "Could not get working directory, try reconnect");
                    return "";
                }
            }
            return "";
        }


        /******** EXTERNAL OBJECT PUBLIC METHODS - END ********/

        private void SetupChannelSftp(SftpOptions options, bool useKey)
        {




            List<AuthenticationMethod> method = new List<AuthenticationMethod>();

            if (useKey)
            {

                PrivateKeyFile keyFile = new PrivateKeyFile(options.KeyPath, options.KeyPassword);
                method.Add(new PrivateKeyAuthenticationMethod(options.User, keyFile));



            }
            else
            {
                method.Add(new PasswordAuthenticationMethod(options.User, options.Password));
            }


            ConnectionInfo con = new ConnectionInfo(options.Host, options.Port, options.User, method.ToArray());



            if (options.AllowHostKeyChecking)
            {
                if (SecurityUtils.compareStrings("", options.KnownHostsPath))
                {
                    this.error.setError("SF009", "Options misconfiguration, known_hosts path is empty but host key checking is true");
                    return;
                }



                checkFingerpint(con, options.KnownHostsPath);
                if (this.fingerprint)
                {
                    this.channel = new Renci.SshNet.SftpClient(con);
                }


            }
            else
            {
                this.channel = new Renci.SshNet.SftpClient(con);
            }



        }

        private string GetFileNamne(string path)
        {
            string[] pathArr = null;
            if (path.Contains("/"))
            {
                pathArr = path.Split('/');
            }
            else
            {
                pathArr = path.Split('\\');
            }

            return pathArr.Last().ToString();
        }

        private static bool CanTrustHost(string hostname, HostKeyEventArgs e)
        {
            if (_knownHosts.Knows(hostname, e.HostKeyName, e.HostKey, 22))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        private void checkFingerpint(ConnectionInfo con, string knownHostsPath)
        {
            _knownHosts = new KnownHostStore(knownHostsPath);
            using (Renci.SshNet.SftpClient client1 = new Renci.SshNet.SftpClient(con))
            {
                client1.HostKeyReceived += (sender, eventArgs) =>
                {
                    eventArgs.CanTrust = CanTrustHost(client1.ConnectionInfo.Host, eventArgs);
                };

                try
                {
                    client1.Connect();
                    this.fingerprint = true;

                }
                catch (Exception)
                {

                    this.error.setError("SF012", "unknown host");
                    this.channel = null;
                    this.fingerprint = false;
                }
                finally
                {
                    client1.Disconnect();
                }

            }
        }


    }

}
