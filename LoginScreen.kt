import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.*

fun main() {
    val userManager = SecureConsoleUserManager("users.txt", "log.txt")

    while (true) {
        println("\n=== Secure Console Login ===")
        println("1. Register")
        println("2. Login")
        println("3. Forgot Password")
        println("4. View Logs")
        println("5. Exit")
        print("Choose an option: ")

        when (readLine()?.trim()) {
            "1" -> {
                print("Enter email: ")
                val email = readLine()!!.trim()
                print("Enter password: ")
                val password = readLine()!!.trim()
                println(userManager.register(email, password))
            }

            "2" -> {
                print("Enter email: ")
                val email = readLine()!!.trim()
                print("Enter password: ")
                val password = readLine()!!.trim()
                val result = userManager.login(email, password)
                println(result)

                if (result.startsWith("✅")) {
                    while (true) {
                        println("\n-- Account Options --")
                        println("1. Change Password")
                        println("2. Delete Account")
                        println("3. Logout")
                        print("Select: ")

                        when (readLine()?.trim()) {
                            "1" -> {
                                print("Enter current password: ")
                                val current = readLine()!!.trim()
                                print("Enter new password: ")
                                val newPass = readLine()!!.trim()
                                println(userManager.changePassword(email, current, newPass))
                            }
                            "2" -> {
                                print("Are you sure? (yes/no): ")
                                if (readLine()?.trim().equals("yes", ignoreCase = true)) {
                                    print("Confirm password: ")
                                    val confirmPassword = readLine()!!.trim()
                                    println(userManager.deleteAccount(email, confirmPassword))
                                    break
                                }
                            }
                            "3" -> break
                            else -> println("Invalid option")
                        }
                    }
                }
            }

            "3" -> {
                print("Enter email: ")
                val email = readLine()!!.trim()
                println(userManager.recoverPassword(email))
            }

            "4" -> {
                println("\n--- LOG ---")
                println(userManager.getLogs())
            }

            "5" -> {
                println("Goodbye!")
                return
            }

            else -> println("Invalid option")
        }
    }
}

class SecureConsoleUserManager(private val fileName: String, private val logFileName: String) {
    private val users = mutableMapOf<String, Pair<String, String>>() // email -> (salt, hashedPassword)
    private val failedAttempts = mutableMapOf<String, Int>()
    private val maxAttempts = 3

    init {
        loadUsers()
    }

    fun register(email: String, password: String): String {
        if (!isValidEmail(email)) return "Invalid email format."
        if (users.containsKey(email)) return "User already exists."
        if (password.isBlank()) return "Password must not be empty."

        val salt = generateSalt()
        val hash = hash(salt + password)
        users[email] = salt to hash
        saveUsers()
        log("Registered: $email")
        return "✅ Registration successful."
    }

    fun login(email: String, password: String): String {
        if (!isValidEmail(email)) return "Invalid email format."

        val user = users[email] ?: return "No account found."
        if ((failedAttempts[email] ?: 0) >= maxAttempts) {
            log("Locked out: $email")
            return "❌ Too many failed attempts. Account locked."
        }

        val (salt, correctHash) = user
        val inputHash = hash(salt + password)

        return if (inputHash == correctHash) {
            failedAttempts[email] = 0
            log("Login success: $email")
            "✅ Login successful. Welcome, $email!"
        } else {
            val attempts = failedAttempts.getOrDefault(email, 0) + 1
            failedAttempts[email] = attempts
            log("Login failed: $email")
            "❌ Incorrect password. Attempts left: ${maxAttempts - attempts}"
        }
    }

    fun changePassword(email: String, currentPassword: String, newPassword: String): String {
        val user = users[email] ?: return "User not found."
        val (salt, correctHash) = user
        val currentHash = hash(salt + currentPassword)

        if (currentHash != correctHash) return "❌ Current password is incorrect."

        val newSalt = generateSalt()
        val newHash = hash(newSalt + newPassword)
        users[email] = newSalt to newHash
        saveUsers()
        log("Password changed: $email")
        return "🔐 Password changed successfully."
    }

    fun deleteAccount(email: String, password: String): String {
        val user = users[email] ?: return "User not found."
        val (salt, correctHash) = user
        val inputHash = hash(salt + password)

        return if (inputHash == correctHash) {
            users.remove(email)
            saveUsers()
            log("Account deleted: $email")
            "🗑️ Account for $email deleted successfully."
        } else {
            "❌ Incorrect password. Account not deleted."
        }
    }

    fun recoverPassword(email: String): String {
        if (!isValidEmail(email)) return "Invalid email format."
        return if (users.containsKey(email)) {
            log("Recovery requested: $email")
            "📧 Password recovery simulated for $email."
        } else {
            "No account found with this email."
        }
    }

    fun getLogs(): String {
        val file = File(logFileName)
        return if (file.exists()) file.readText() else "No logs yet."
    }

    private fun saveUsers() {
        File(fileName).printWriter().use { out ->
            users.forEach { (email, pair) ->
                val (salt, hash) = pair
                out.println("$email:$salt:$hash")
            }
        }
    }

    private fun loadUsers() {
        val file = File(fileName)
        if (!file.exists()) return
        file.forEachLine {
            val parts = it.split(":")
            if (parts.size == 3) users[parts[0]] = parts[1] to parts[2]
        }
    }

    private fun hash(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(input.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    private fun generateSalt(length: Int = 16): String {
        val bytes = ByteArray(length).also { SecureRandom().nextBytes(it) }
        return Base64.getEncoder().encodeToString(bytes)
    }

    private fun isValidEmail(email: String): Boolean {
        return Regex("^[\\w.-]+@[\\w.-]+\\.[a-zA-Z]{2,}$").matches(email)
    }

    private fun log(message: String) {
        val timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))
        File(logFileName).appendText("[$timestamp] $message\n")
    }
}