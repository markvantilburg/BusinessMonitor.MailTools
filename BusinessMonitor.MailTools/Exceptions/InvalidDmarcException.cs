namespace BusinessMonitor.MailTools.Exceptions
{
    public class InvalidDmarcException : Exception
    {
        public InvalidDmarcException()
        {
        }

        public InvalidDmarcException(string message)
            : base(message)
        {
        }

        public InvalidDmarcException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
