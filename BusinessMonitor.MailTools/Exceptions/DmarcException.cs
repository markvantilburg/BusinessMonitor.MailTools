namespace BusinessMonitor.MailTools.Exceptions
{
    public class DmarcException : Exception
    {
        public DmarcException()
        {
        }

        public DmarcException(string message)
            : base(message)
        {
        }

        public DmarcException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
