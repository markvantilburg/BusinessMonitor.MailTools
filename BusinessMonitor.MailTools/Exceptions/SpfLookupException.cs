namespace BusinessMonitor.MailTools.Exceptions
{
    public class SpfLookupException : SpfException
    {
        public SpfLookupException()
        {
        }

        public SpfLookupException(string message)
            : base(message)
        {
        }

        public SpfLookupException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
