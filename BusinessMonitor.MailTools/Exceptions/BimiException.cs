namespace BusinessMonitor.MailTools.Exceptions
{
    public class BimiException : Exception
    {
        public BimiException()
        {
        }

        public BimiException(string message)
            : base(message)
        {
        }

        public BimiException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
