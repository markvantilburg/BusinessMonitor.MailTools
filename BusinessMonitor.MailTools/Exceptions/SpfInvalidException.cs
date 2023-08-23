namespace BusinessMonitor.MailTools.Exceptions
{
    public class SpfInvalidException : SpfException
    {
        public SpfInvalidException()
        {
        }

        public SpfInvalidException(string message)
            : base(message)
        {
        }

        public SpfInvalidException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
