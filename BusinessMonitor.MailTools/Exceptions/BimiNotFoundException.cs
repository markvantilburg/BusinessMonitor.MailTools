namespace BusinessMonitor.MailTools.Exceptions
{
    public class BimiNotFoundException : BimiException
    {
        public BimiNotFoundException()
        {
        }

        public BimiNotFoundException(string message)
            : base(message)
        {
        }

        public BimiNotFoundException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
