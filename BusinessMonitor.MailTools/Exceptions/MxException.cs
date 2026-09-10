namespace BusinessMonitor.MailTools.Exceptions
{
    public class MxException : Exception
    {
        public MxException()
        {
        }

        public MxException(string message)
            : base(message)
        {
        }

        public MxException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
