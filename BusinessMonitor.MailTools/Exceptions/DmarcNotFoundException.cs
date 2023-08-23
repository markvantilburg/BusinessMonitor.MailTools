namespace BusinessMonitor.MailTools.Exceptions
{
    public class DmarcNotFoundException : DmarcException
    {
        public DmarcNotFoundException()
        {
        }

        public DmarcNotFoundException(string message)
            : base(message)
        {
        }

        public DmarcNotFoundException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
