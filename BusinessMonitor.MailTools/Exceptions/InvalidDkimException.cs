namespace BusinessMonitor.MailTools.Exceptions
{
    public class InvalidDkimException : Exception
    {
        public InvalidDkimException()
        {
        }

        public InvalidDkimException(string message)
            : base(message)
        {
        }

        public InvalidDkimException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
