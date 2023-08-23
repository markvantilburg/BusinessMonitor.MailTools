namespace BusinessMonitor.MailTools.Exceptions
{
    public class SpfNotFoundException : SpfException
    {
        public SpfNotFoundException()
        {
        }

        public SpfNotFoundException(string message)
            : base(message)
        {
        }

        public SpfNotFoundException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
