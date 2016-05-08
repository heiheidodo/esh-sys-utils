/**
* esh - the 'extensible' shell.
*
* Utility functions for system calls.
*
* Developed by Godmar Back for CS 3214 Fall 2009
* Virginia Tech.
*/
#include "esh-sys-utils.h"

/* List of constant statuses to use throughout the program. */
static const char *STATUSES[] = {"Foreground", "Running", "Stopped"};

/* Utility function for esh_sys_fatal_error and esh_sys_error */
static void
vesh_sys_error(char *fmt, va_list ap)
{
char errmsg[1024];

strerror_r(errno, errmsg, sizeof errmsg);
vfprintf(stderr, fmt, ap);
fprintf(stderr, "%s\n", errmsg);
}

/* Print information about the last syscall error */
void
esh_sys_error(char *fmt, ...)
{
va_list ap;
va_start(ap, fmt);
vesh_sys_error(fmt, ap);
va_end(ap);
}

/* Print information about the last syscall error and then exit */
void
esh_sys_fatal_error(char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vesh_sys_error(fmt, ap);
    va_end(ap);
    exit(EXIT_FAILURE);
}

static int terminal_fd = -1; /* the controlling terminal */

static struct termios saved_tty_state; /* the state of the terminal when shell
was started. */

/* Initialize tty support. Return pointer to saved initial terminal state */
struct termios *
esh_sys_tty_init(void)
{
    char *tty;
    assert(terminal_fd == -1 || !!!"esh_sys_tty_init already called");

    terminal_fd = open(tty = ctermid(NULL), O_RDWR);
    if (terminal_fd == -1)
        esh_sys_fatal_error("opening controlling terminal %s failed: ", tty);

    esh_sys_tty_save(&saved_tty_state);
    return &saved_tty_state;
}

/* Save current terminal settings.
* This function is used when a job is suspended.*/
void
esh_sys_tty_save(struct termios *saved_tty_state)
{
    int rc = tcgetattr(terminal_fd, saved_tty_state);
    if (rc == -1)
        esh_sys_fatal_error("tcgetattr failed: ");
}

/* Restore terminal to saved settings.
* This function is used when resuming a suspended job. */
void
esh_sys_tty_restore(struct termios *saved_tty_state)
{
    int rc;

retry:
    rc = tcsetattr(terminal_fd, TCSADRAIN, saved_tty_state);
    if (rc != -1)
	{
		// do nothing
	}
	else
	{
        if (errno == EINTR)
		{
            goto retry;
		}
        esh_sys_fatal_error("could not restore tty attributes tcsetattr: ");
    }
}

/* Get a file descriptor that refers to controlling terminal */
int
esh_sys_tty_getfd(void)
{
    assert(terminal_fd != -1 || !!!"esh_sys_tty_init() must be called");
    return terminal_fd;
}

/* Return true if this signal is blocked */
bool
esh_signal_is_blocked(int sig)
{
    sigset_t mask;
    if (sigprocmask(0, NULL, &mask) == -1)
        esh_sys_error("sigprocmask failed while retrieving current mask");

    return sigismember(&mask, sig);
}

/* Helper for esh_signal_block and esh_signal_unblock */
static bool
__mask_signal(int sig, int how)
{
    sigset_t mask, omask;
    sigemptyset(&mask);
    sigaddset(&mask, sig);
    if (sigprocmask(how, &mask, &omask) != 0)
        esh_sys_error("sigprocmask failed for %d/%d", sig, how);
    return sigismember(&omask, sig);
}

/* Block a signal. Returns true it was blocked before */
bool
esh_signal_block(int sig)
{
    return __mask_signal(sig, SIG_BLOCK);
}

/* Unblock a signal. Returns true it was blocked before */
bool
esh_signal_unblock(int sig)
{
    return __mask_signal(sig, SIG_UNBLOCK);
}

/* Install signal handler for signal 'sig' */
void
esh_signal_sethandler(int sig, sa_sigaction_t handler)
{
    sigset_t emptymask;

    sigemptyset(&emptymask);
    struct sigaction sa = {
        .sa_sigaction = handler,
        /* do not block any additional signals (besides 'sig') when
* signal handler is entered. */
        .sa_mask = emptymask,
        /* restart system calls when possible */
        .sa_flags = SA_RESTART | SA_SIGINFO
    };

    if (sigaction(sig, &sa, NULL) != 0)
        esh_sys_fatal_error("sigaction failed for signal %d", sig);
}

void wait_for_job(struct termios *sysTTY)
{
	int status;
	pid_t pid;

	bool valid;
	valid = (pid = waitpid(-1, &status, WUNTRACED)) > 0;

	if (!valid)
	{
		//error
	}
	else
	{
		give_terminal_to(getpgrp(), sysTTY);
		child_status_change(pid, status);
	}
}

void child_status_change(pid_t pid, int status)
{
	if (pid < 0)
	{		
		esh_sys_fatal_error(PID_ERROR);
	}
	else if (pid > 0)
	{
		INIT_LISTELEM(&currentJobs);

		for (LISTELEM_BEGIN(&currentJobs)LISTELEM_END)
		{
			struct esh_pipeline *myPipe;
			myPipe = list_entry(listElem, struct esh_pipeline, elem);

			bool valid;
			valid = (myPipe->pgrp == pid);

			if (WIFSTOPPED(status) && valid)
			{
				if (WSTOPSIG(status) != 22) 
				{
					printf("\n[%d]+ Stopped ", myPipe->jid);
					myPipe->status = STOPPED;
					printJobFromList(currentJobs);
				}
				else
				{
					myPipe->status = STOPPED;
				}
			}

			if (valid && WTERMSIG(status) == 9)
			{	
				list_remove(listElem);
			}
			else if(valid && WIFEXITED(status))
			{
				list_remove(listElem);
			}
			else if (valid && WIFSIGNALED(status))
			{
				list_remove(listElem);
			}
			else if (valid && WIFCONTINUED(status))
			{
				list_remove(listElem);
			}
			if (!jobsExist() && valid) 
			{
				jid = 0;
			}
		}
	}
}

void give_terminal_to(pid_t pgrp, struct termios *pg_tty_state)
{
esh_signal_block(SIGTTOU);
int rc = tcsetpgrp(esh_sys_tty_getfd(), pgrp);

if (rc == -1)
{
	esh_sys_fatal_error("tcsetpgrp: ");
}

if (pg_tty_state)
{
	esh_sys_tty_restore(pg_tty_state);
}

esh_signal_unblock(SIGTTOU);
}

bool jobsExist()
{
	if (list_empty(&currentJobs))
	{
		return false;
	}
	return true;
}

void sigchld_handler(int sig, siginfo_t *info, void *_ctxt)
{
	int status;
	pid_t pid;

	assert(sig == SIGCHLD);

	while ((pid = waitpid(-1, &status, WUNTRACED|WNOHANG)) > 0)
	{
		child_status_change(pid, status);
	}
}

int getCommandType(char *command_name)
{
	if(strcmp(command_name, "exit") == 0)
	{
		return 1;
	}
	if(strcmp(command_name, "jobs") == 0)
	{
		return 2;
	}
	if(strcmp(command_name, "fg") == 0)
	{
		return 3;
	}
	if(strcmp(command_name, "bg") == 0)
	{
		return 4;
	}
	if(strcmp(command_name, "kill") == 0)
	{
		return 5;
	}
	if(strcmp(command_name, "stop") == 0)
	{
		return 6;
	}
	return 0; 
}

void printJobFromList(struct list jobList)
{
	printf("(");

	struct esh_pipeline *myPipe;
	struct list_elem *listElem;
	listElem = list_begin(&jobList);

	myPipe = list_entry(listElem, struct esh_pipeline, elem);
	listElem = list_begin(&myPipe->commands);

	for (LISTELEM_BEGIN(&myPipe->commands)LISTELEM_END)
	{
		struct esh_command *currentCommand;
		currentCommand = list_entry(listElem, struct esh_command, elem);

		char **arguments;
		arguments = currentCommand->argv;

		while (*arguments)
		{
			printf("%s ", *arguments); 
			arguments++;
		}

		if (list_size(&myPipe->commands) > 1)
		printf("| "); 
	}

	printf(")\n"); 
}

void printJobFromPipe(struct esh_pipeline *pipe)
{
	printf("(");

	struct list_elem *listElem;
	listElem = list_begin(&pipe->commands);

	for(LISTELEM_BEGIN(&pipe->commands)LISTELEM_END)
	{
		struct esh_command *currentCommand;
		currentCommand = list_entry(listElem, struct esh_command, elem);

		char **arguments;
		arguments = currentCommand->argv;

		while(*arguments)
		{
			printf("%s ", *arguments); 
			arguments++;
		}

		if(list_size(&pipe->commands) > 1)
		{
			printf("| ");
		}
	}

	printf(")\n"); 
	
}

void foreGroundCommand(struct esh_pipeline *myPipe,
struct termios *sysTTY)
{
	esh_signal_block(SIGCHLD);
	myPipe->status = FOREGROUND;

	printJobFromPipe(myPipe);
	give_terminal_to(myPipe->pgrp, sysTTY);
	killCmd(myPipe, SIGCONT);

	if (kill(myPipe->pgrp, SIGCONT) != -1)
	{
		// right track
	}
	else
	{
		esh_sys_fatal_error(FOREGROUND_ERROR);
	}
	
	wait_for_job(sysTTY);
	esh_signal_unblock(SIGCHLD);
}

void runJobsCommand()
{
	struct list_elem *listElem;
	listElem = list_begin(&currentJobs);

	for(LISTELEM_BEGIN(&currentJobs)LISTELEM_END)
	{
		struct esh_pipeline *myPipe;
		myPipe = list_entry(listElem, struct esh_pipeline, elem);

		printf("[%d] %s ", myPipe->jid, STATUSES[myPipe->status]);

		printJobFromPipe(myPipe);
	}
}

int isFgBgKillStop(int commandType)
{
	return (commandType == 3 || commandType == 4 ||
commandType == 5 || commandType == 6);
}

void killCmd(struct esh_pipeline *myPipe, int SIGNAL)
{
	char * command;
	if (SIGNAL == SIGCONT)
	{
		command = "SIGCONT";
	}
	else if (SIGNAL == SIGKILL)
	{
		command = "SIGKILL";
	}
	else if (SIGNAL == SIGSTOP)
	{
		command = "SIGSTOP";
	}
/*
	switch(SIGNAL)
	{
		case SIGCONT:
		command = "SIGCONT";
		break;

		case SIGKILL:
		command = "SIGKILL";
		break;

		case SIGSTOP:
		command = "SIGSTOP";
		break;
	}
*/
	if (kill(myPipe->pgrp, SIGNAL) != -1)
	{
		// DO nothing
	}
	else
	{
		esh_sys_fatal_error("%s ERROR ", command);
	}
}

//if statement
bool stringContains(char *string, char *value)
{
	if (strncmp(string, value, 1) == 0)
	{
		return true;
	}
	return false;
}

int getJobArgumentId(struct esh_command *commands)
{
	int jobArgumentId = -1;

	if (commands->argv[1] == NULL)
	{
		struct list_elem *listElem;
		listElem = list_back(&currentJobs);

		struct esh_pipeline *pipeline;
		pipeline = list_entry(listElem, struct esh_pipeline, elem);

		jobArgumentId = pipeline->jid;
	}
	else if (!stringContains(commands->argv[1], "%"))
   {
		jobArgumentId = atoi(commands->argv[1]);
	}
	else
	{
		char *argId;
		argId = (char*) malloc(5);

		strcpy(argId, 1 + commands->argv[1]);

		jobArgumentId = atoi(argId);
		free(argId);
	}

	return jobArgumentId;
}

void handleBuiltinCommands(struct esh_pipeline *myPipe,
int commandType,
struct esh_command *commands,
struct termios *sysTTY)
{
	myPipe = getPipeline(commands);

	if (commandType == 3)
	{
		foreGroundCommand(myPipe, sysTTY);
	}
	else if (commandType == 4)
	{
		myPipe->status = BACKGROUND;
		printJobFromList(currentJobs);
		killCmd(myPipe, SIGCONT);
	}
	else if (commandType == 5)
	{
		killCmd(myPipe, SIGKILL);
	}
	else if (commandType == 6)
	{
		killCmd(myPipe, SIGSTOP);
	}
}

struct esh_pipeline* getPipeline(struct esh_command *commands)
{
	struct esh_pipeline *ret;
	ret = NULL;

	int jobArgumentId;
	jobArgumentId = getJobArgumentId(commands);

	INIT_LISTELEM(&currentJobs);

	for (LISTELEM_BEGIN(&currentJobs)LISTELEM_END)
	{
		struct esh_pipeline *job;
		job = list_entry(listElem, struct esh_pipeline, elem);

		if (job->jid != jobArgumentId)
		{
			// do nothing
		}
		else
		{
			ret = job;
			break;
		}
	}

	return ret;
}


void updatePipelineProcessGroup(struct esh_command *command,
struct esh_pipeline *myPipe)
{
	pid_t pid;
	pid = getpid();
	command->pid = pid;

	if (myPipe->pgrp != -1)
	{
		// do nothing
	}
	else
	{
		myPipe->pgrp = pid;
	}
	if (setpgid(pid, myPipe->pgrp) < 0)
	{
		esh_sys_fatal_error(PROCESSGRP_ERROR);
	}
}

void updatePipelineStatus(struct termios *sysTTY,
struct esh_pipeline *myPipe)
{
	if (myPipe->bg_job)
	{
		myPipe->status = BACKGROUND;
	}
	else
	{
		give_terminal_to(myPipe->pgrp, sysTTY);
		myPipe->status = FOREGROUND;
		return;
	}
}

void handleIoredInput(struct esh_command *command)
{
	if (command->iored_input == NULL)
	{
		// nothing 
	}
	else
	{
		int in_fd;
		in_fd = open(command->iored_input, O_RDONLY);

		if (dup2(in_fd, 0) >= 0)
		{
			// do nothing but close
		}
		else
		{
			esh_sys_fatal_error(DUP2_ERROR);
		}
		close(in_fd);
	}
}

void handleIoredOutput(struct esh_command *command)
{
	if (command->iored_output == NULL)
	{
		// do nothing
	}
	else
	{
		int out_fd;
		if (command->append_to_output)
		{
			out_fd = open(command->iored_output, 
						OFLAGS | O_APPEND, ACCESS_PERMISH);
		}
		else
		{
			out_fd = open(command->iored_output, OFLAGS | O_TRUNC
							, ACCESS_PERMISH);
		}
		
		if (dup2(out_fd, 1) >= 0)
		{
			// right track
		}
		else
		{
			esh_sys_fatal_error(DUP2_ERROR);
		}
		close(out_fd);
	}
}

void hPent(struct esh_pipeline *pipeline,
int pid,
bool isPiped,
int *oldPipe, int *newPipe,
struct list_elem *listElem)
{
	if (pipeline->pgrp != -1)
	{
		// error
	}
	else
	{
		pipeline->pgrp = pid;
	}
	if (setpgid(pid, pipeline->pgrp) < 0)
	{
		esh_sys_fatal_error(PROCESSGRP_ERROR);
	}
	if(!isPiped)
	{
		// do nothing
	}
	else
	{
		if (listElem != list_begin(&pipeline->commands))
		{
			close(oldPipe[0]);
			close(oldPipe[1]);
		}
		if (list_next(listElem) == list_tail(&pipeline->commands))
		{
			close(oldPipe[0]);
			close(oldPipe[1]);
			close(newPipe[0]);
			close(newPipe[1]);
		}
		if (list_next(listElem) != list_tail(&pipeline->commands))
		{
			oldPipe[0] = newPipe[0];
			oldPipe[1] = newPipe[1];
		}
	}
}

void hCld(struct esh_pipeline *myPipe,
struct esh_command *command,
struct termios *sysTTY,
bool isPiped,
int *oldPipe, int *newPipe,
struct list_elem *listElem)
{

	updatePipelineProcessGroup(command, myPipe);
	updatePipelineStatus(sysTTY, myPipe);
	
	if(!isPiped)
	{
		// do nothing 
	}
	else
	{
		if (listElem != list_begin(&myPipe->commands))
		{
			close(oldPipe[1]);
			dup2(oldPipe[0], 0);
			close(oldPipe[0]);
		}
		if (list_next(listElem) != list_tail(&myPipe->commands))
		{
			close(newPipe[0]);
			dup2(newPipe[1], 1);
			close(newPipe[1]);
		}
	}

	handleIoredInput(command); 
	handleIoredOutput(command); 

	execvp(command->argv[0], command->argv);
}

void pipeAndForkCommands(struct esh_pipeline *pipeline,
struct termios *sysTTY)
{
	struct esh_command *command;
	bool isPiped;
	pid_t pid;
	pipeline->jid = jid;
	pipeline->pgrp = -1;
	int oldPipe[2];
	int newPipe[2];
	isPiped = (list_size(&pipeline->commands) > 1);

	INIT_LISTELEM(&pipeline->commands);

	for (LISTELEM_BEGIN(&pipeline->commands)LISTELEM_END)
	{	
		command = list_entry(listElem, struct esh_command, elem);

		if((list_next(listElem) != list_tail(&pipeline->commands)) && isPiped)
		{
			pipe(newPipe);
		}
		esh_signal_block(SIGCHLD);

		pid = fork();

		if (pid == 0)
		{
			hCld(pipeline, command, sysTTY, isPiped, oldPipe, newPipe, listElem);
		}
		else if (pid >= 0)
		{
			hPent(pipeline, pid, isPiped, oldPipe, newPipe, listElem);
		}
		else
		{
			esh_sys_fatal_error(FORK_ERROR);
		}
	}
}

void hOther(struct esh_pipeline *pipeline,
struct termios *sysTTY,
struct list_elem * listElem,
struct esh_command_line * commandLine)
{
	esh_signal_sethandler(SIGCHLD, sigchld_handler);
	jid = (!jobsExist()) ? 1 : (jid + 1);
	pipeAndForkCommands(pipeline, sysTTY);

	if (pipeline->bg_job)
	{
		pipeline->status = BACKGROUND;
		printf("[%d] %d\n", pipeline->jid, pipeline->pgrp);
	}
	listElem = list_pop_front(&commandLine->pipes);
	list_push_back(&currentJobs, listElem);
	if (!pipeline->bg_job)
	{
		wait_for_job(sysTTY);
	}
	esh_signal_unblock(SIGCHLD);
}

void handleCommands(struct esh_pipeline *myPipe, int commandType,
struct esh_command *cmd,
struct esh_command_line * commandLine,
struct termios *sysTTY,
struct list_elem* listElem)
{
	if (commandType == 1)
	{
		exit(EXIT_SUCCESS);
	}
	else if (commandType == 2)
	{
		runJobsCommand();
	}
	else if (jobsExist() && isFgBgKillStop(commandType))
	{
		handleBuiltinCommands(myPipe, commandType, cmd, sysTTY);
	}
	else if (commandType == 0)
	{
		hOther(myPipe, sysTTY, listElem, commandLine);
	}
}

char * buildPromptWithPlugins(void)
{
	char *prompt;
	prompt = NULL;

	INIT_LISTELEM(&esh_plugin_list);

	for (LISTELEM_BEGIN(&esh_plugin_list)LISTELEM_END)
	{
		struct esh_plugin *plugin;
		plugin = list_entry(listElem, struct esh_plugin, elem);

		bool needPlugin;
		needPlugin = (plugin->make_prompt != NULL);

		if (needPlugin)
		{
			char * plug;
			plug = plugin->make_prompt();
			bool valid;
			valid = (prompt != NULL);
			if (prompt == NULL)
			{
				prompt = plug;
			}
			else
			{
				prompt = realloc(prompt, 1 + strlen(plug) + strlen(prompt));
			}
				
			if(valid)
			{

				strcat(prompt, plug);	
				free(plug);
			}
		}
	}
	if (prompt == NULL)
	{
		return strdup("esh> ");
	}
	return prompt;
}

void pluginProcessor(struct list_elem * listElem,
struct esh_command *commands,
int commandType)
{
	for (LISTELEM_BEGIN(&esh_plugin_list)LISTELEM_END)
	{
		struct esh_plugin *plugin;
		plugin = list_entry(listElem, struct esh_plugin, elem);
		plugin->process_builtin(commands);
	}
}