namespace BusinessMonitor.MailTools.Exceptions
{
    public class BimiInvalidException : BimiException
    {
        public BimiInvalidException()
        {
        }

        public BimiInvalidException(string message)
            : base(message)
        {
        }

        public BimiInvalidException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
