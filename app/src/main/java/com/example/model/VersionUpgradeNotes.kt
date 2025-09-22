package com.example.model

/**
 * Data model class for version upgrade notes that holds information about version changes
 */
data class VersionUpgradeNotes(
    val version: String,
    val title: String,
    val releaseDate: String,
    val keyChanges: List<String>,
    val improvements: List<String>,
    val bugFixes: List<String>,
    val breakingChanges: List<String> = emptyList(),
    val additionalNotes: String = ""
) {
    /**
     * Returns true if this version has any breaking changes
     */
    fun hasBreakingChanges(): Boolean = breakingChanges.isNotEmpty()
    
    /**
     * Returns a formatted summary of all changes
     */
    fun getChangesSummary(): String {
        val summary = StringBuilder()
        
        if (keyChanges.isNotEmpty()) {
            summary.append("Key Changes:\n")
            keyChanges.forEach { change ->
                summary.append("• $change\n")
            }
            summary.append("\n")
        }
        
        if (improvements.isNotEmpty()) {
            summary.append("Improvements:\n")
            improvements.forEach { improvement ->
                summary.append("• $improvement\n")
            }
            summary.append("\n")
        }
        
        if (bugFixes.isNotEmpty()) {
            summary.append("Bug Fixes:\n")
            bugFixes.forEach { fix ->
                summary.append("• $fix\n")
            }
            summary.append("\n")
        }
        
        if (breakingChanges.isNotEmpty()) {
            summary.append("⚠️ Breaking Changes:\n")
            breakingChanges.forEach { change ->
                summary.append("• $change\n")
            }
            summary.append("\n")
        }
        
        if (additionalNotes.isNotEmpty()) {
            summary.append("Additional Notes:\n$additionalNotes")
        }
        
        return summary.toString().trim()
    }
}