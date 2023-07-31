namespace BusinessMonitor.MailTools.Exceptions
{
    public class InvalidSpfException : Exception
    {
        public InvalidSpfException()
        {
        }

        public InvalidSpfException(string message)
            : base(message)
        {
        }

        public InvalidSpfException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
