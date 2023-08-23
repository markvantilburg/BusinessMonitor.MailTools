namespace BusinessMonitor.MailTools.Exceptions
{
    public class SpfException : Exception
    {
        public SpfException()
        {
        }

        public SpfException(string message)
            : base(message)
        {
        }

        public SpfException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
