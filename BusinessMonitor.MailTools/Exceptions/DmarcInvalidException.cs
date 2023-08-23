namespace BusinessMonitor.MailTools.Exceptions
{
    public class DmarcInvalidException : DmarcException
    {
        public DmarcInvalidException()
        {
        }

        public DmarcInvalidException(string message)
            : base(message)
        {
        }

        public DmarcInvalidException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
