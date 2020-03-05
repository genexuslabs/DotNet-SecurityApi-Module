using FluentFTP;
using GeneXusFtps.GeneXusCommons;
using GeneXusFtps.GeneXusFtpsUtils;
using SecurityAPICommons.Utils;
using System;
using System.IO;
using System.Net;
using System.Security;
using System.Security.Authentication;
using System.Text;

namespace GeneXusFtps.GeneXusFtps
{
    [SecuritySafeCritical]
    public class FtpsClient : IFtpsClientObject
    {
        private FtpClient client;
        private string pwd;

        [SecuritySafeCritical]
        public FtpsClient() : base()
        {
            this.client = null;
        }

        /******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/
        [SecuritySafeCritical]
        public override bool Connect(FtpsOptions options)
        {
            if (options.HasError())
            {
                this.error = options.GetError();
                return false;
            }
            if (SecurityUtils.compareStrings("", options.Host) || SecurityUtils.compareStrings("", options.User)
                    || SecurityUtils.compareStrings("", options.Password))
            {
                this.error.setError("FS001", "Empty connection data");
                return false;
            }

            this.client = new FtpClient
            {
                Host = options.Host,
                Port = options.Port,
                Credentials = new NetworkCredential(options.User, options.Password),
                DataConnectionType = SetConnectionMode(options),
                EncryptionMode = SetEncryptionMode(options),
                Encoding = Encoding.UTF8,
            };

            this.client.DownloadDataType = SetEncoding(options);
            this.client.SslProtocols = SetProtocol(options);
            this.client.DataConnectionEncryption = options.ForceEncryption;
            this.client.ValidateCertificate += Client_ValidateCertificate;
            try
            {
                this.client.Connect();
                if (!this.client.LastReply.Success)
                {
                    this.client.Disconnect();
                    this.error.setError("FS008", "Connection error");
                    return false;
                }
            }
            catch (Exception e)
            {
                this.error.setError("FS002", "Connection error " + e.Message);
                this.client = null;
                return false;
            }
            if (!this.client.IsConnected)
            {
                this.error.setError("FS009", "Connection error");
                return false;
            }
            return true;
        }





        [SecuritySafeCritical]
        public override bool Put(string localPath, string remoteDir)
        {
            if (this.client == null || !this.client.IsConnected)
            {
                this.error.setError("FS003", "The connection is invalid, reconect");
                return false;
            }
            try
            {
                if (!IsSameDir(remoteDir, this.client.GetWorkingDirectory()))
                {
                    this.client.SetWorkingDirectory(remoteDir);

                    this.pwd = remoteDir;
                }
            }
            catch (Exception e)
            {
                this.error.setError("FS013", "Error changing directory " + e.Message);
                return false;
            }
            bool isStored = false;
            try
            {
                isStored = this.client.Upload(new FileStream(localPath, FileMode.Open), AddFileName(localPath, remoteDir), FtpRemoteExists.Overwrite, true);
                if (!isStored)
                {
                    this.error.setError("FS012", " Reply String: " + this.client.LastReply);
                }
            }
            catch (Exception e1)
            {
                this.error.setError("FS004", "Erorr uploading file to server " + e1.Message);
                return false;
            }
            return isStored;
        }

        [SecuritySafeCritical]
        public override bool Get(string remoteFilePath, string localDir)
        {
            if (this.client == null || !this.client.IsConnected)
            {
                this.error.setError("FS010", "The connection is invalid, reconect");
                return false;
            }
            try
            {
                if (!IsSameDir(Path.GetDirectoryName(remoteFilePath), this.client.GetWorkingDirectory()))
                {
                    this.client.SetWorkingDirectory(Path.GetDirectoryName(remoteFilePath));

                    this.pwd = Path.GetDirectoryName(remoteFilePath);
                }
            }
            catch (Exception e)
            {
                this.error.setError("FS013", "Error changing directory " + e.Message);
                return false;
            }

            FileStream fileStream = File.Create(AddFileName(remoteFilePath, localDir));
            bool isDownloaded = false;
            try
            {
                isDownloaded = this.client.Download(fileStream, remoteFilePath, 0);
            }
            catch (Exception e1)
            {
                this.error.setError("FS005", "Error retrieving file " + e1.Message);
                return false;
            }
            if (fileStream == null || !isDownloaded)
            {
                this.error.setError("FS007", "Could not retrieve file");
                return false;
            }
            return true;
        }

        [SecuritySafeCritical]
        public override void Disconnect()
        {
            this.client.Disconnect();
        }

        [SecuritySafeCritical]
        public override string GetWorkingDirectory()
        {
            if (this.client == null || !this.client.IsConnected)
            {
                this.error.setError("FS007", "The connection is invalid, reconect");
                return "";
            }
            String pwd = "";
            try
            {
                pwd = this.client.GetWorkingDirectory();
            }
            catch (IOException e)
            {
                this.error.setError("FS006", "Could not obtain working directory, try reconnect");
                return "";
            }
            if (pwd == null)
            {
                return this.pwd;
            }
            return pwd;
        }

        /******** EXTERNAL OBJECT PUBLIC METHODS - END ********/


        private FtpDataConnectionType SetConnectionMode(FtpsOptions options)
        {
            FtpConnectionMode mode = options.GetFtpConnectionMode();
            switch (mode)
            {
                case FtpConnectionMode.ACTIVE:
                    return FtpDataConnectionType.AutoActive;
                case FtpConnectionMode.PASSIVE:
                    return FtpDataConnectionType.PASV;
                default:
                    return FtpDataConnectionType.PASV;
            }
        }

        private FluentFTP.FtpEncryptionMode SetEncryptionMode(FtpsOptions options)
        {
            switch (options.GetFtpEncryptionMode())
            {
                case GeneXusFtpsUtils.FtpEncryptionMode.EXPLICIT:
                    return FluentFTP.FtpEncryptionMode.Explicit;

                case GeneXusFtpsUtils.FtpEncryptionMode.IMPLICIT:
                    return FluentFTP.FtpEncryptionMode.Implicit;
                default:
                    return FluentFTP.FtpEncryptionMode.Explicit;
            }
        }

        private FtpDataType SetEncoding(FtpsOptions options)
        {
            switch (options.GetFtpEncoding())
            {
                case FtpEncoding.BINARY:
                    return FtpDataType.Binary;
                case FtpEncoding.ASCII:
                    return FtpDataType.ASCII;
                default:
                    return FtpDataType.Binary;
            }
        }

        private SslProtocols SetProtocol(FtpsOptions options)
        {
            switch (options.GetFtpsProtocol())
            {
                case FtpsProtocol.TLS1_0:
                    return SslProtocols.Tls;
                case FtpsProtocol.TLS1_1:
                    return SslProtocols.Tls11;
                case FtpsProtocol.TLS1_2:
                    return SslProtocols.Tls12;
                case FtpsProtocol.SSLv2:
                    return SslProtocols.Ssl2;
                case FtpsProtocol.SSLv3:
                    return SslProtocols.Ssl3;
                default:
                    return SslProtocols.Tls;
            }
        }

        private bool IsSameDir(String path1, String path2)
        {
            string path11 = Path.GetDirectoryName(path1);
            string path22 = Path.GetDirectoryName(path2);
            return path11.CompareTo(path22) == 0;
        }

        private static void Client_ValidateCertificate(FtpClient control, FtpSslValidationEventArgs e)
        {
            e.Accept = true;
        }

        private Stream PathToStream(string path)
        {

            FileStream stream = new FileStream(path, FileMode.Open);
            return stream;
        }

        private string AddFileName(string originPath, string dir)
        {


            string fileName = Path.GetFileName(originPath);
            if (SecurityUtils.compareStrings("", dir))
            {
                return fileName;
            }
            string pathArr = "";
            if (dir.Contains("/"))
            {
                pathArr = dir + "/" + fileName;
            }
            else
            {
                pathArr = dir + "\\" + fileName;
            }

            return pathArr;
        }

    }
}
