package at.bestsolution.reposilite.auth.gitlab

import com.reposilite.journalist.Channel
import com.reposilite.journalist.Journalist
import com.reposilite.journalist.Logger
import java.io.PrintStream

/**
 * A no-op Journalist for use in tests. Logs to stdout for debugging.
 */
object NoopJournalist : Journalist {

    override fun getLogger(): Logger = StdoutLogger

    private object StdoutLogger : Logger {
        override fun log(channel: Channel, message: Any?, vararg arguments: Any?): Logger {
            println("[$channel] $message")
            return this
        }

        override fun exception(channel: Channel, throwable: Throwable): Logger {
            println("[$channel] ${throwable.message}")
            return this
        }

        override fun setThreshold(channel: Channel): Logger = this

        override fun toPrintStream(channel: Channel): PrintStream = System.out

        override fun getLogger(): Logger = this
    }
}
