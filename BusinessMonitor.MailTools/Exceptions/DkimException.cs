namespace BusinessMonitor.MailTools.Exceptions
{
    public class DkimException : Exception
    {
        public DkimException()
        {
        }

        public DkimException(string message)
            : base(message)
        {
        }

        public DkimException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
