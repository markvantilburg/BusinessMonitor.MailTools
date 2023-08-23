namespace BusinessMonitor.MailTools.Exceptions
{
    public class DkimNotFoundException : DkimException
    {
        public DkimNotFoundException()
        {
        }

        public DkimNotFoundException(string message)
            : base(message)
        {
        }

        public DkimNotFoundException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
