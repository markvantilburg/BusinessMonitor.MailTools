namespace BusinessMonitor.MailTools.Exceptions
{
    public class DkimInvalidException : DkimException
    {
        public DkimInvalidException()
        {
        }

        public DkimInvalidException(string message)
            : base(message)
        {
        }

        public DkimInvalidException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
