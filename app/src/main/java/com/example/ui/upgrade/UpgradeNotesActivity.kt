package com.example.ui.upgrade

import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.example.R
import com.example.model.VersionUpgradeNotes

/**
 * Activity that displays version upgrade notes to users
 * This serves as an example of how to use the VersionUpgradeNotesFragment
 */
class UpgradeNotesActivity : AppCompatActivity() {
    
    companion object {
        private const val EXTRA_UPGRADE_NOTES = "extra_upgrade_notes"
        
        /**
         * Creates an intent to start the UpgradeNotesActivity
         * @param context The context to start the activity from
         * @param upgradeNotes The version upgrade notes to display
         * @return Intent to start the activity
         */
        fun createIntent(context: Context, upgradeNotes: VersionUpgradeNotes): Intent {
            return Intent(context, UpgradeNotesActivity::class.java).apply {
                putExtra(EXTRA_UPGRADE_NOTES, upgradeNotes)
            }
        }
        
        /**
         * Creates sample upgrade notes for demonstration purposes
         */
        fun createSampleUpgradeNotes(): VersionUpgradeNotes {
            return VersionUpgradeNotes(
                version = "2.1.0",
                title = "Major Update",
                releaseDate = "March 15, 2024",
                keyChanges = listOf(
                    "New dark mode theme with improved readability",
                    "Enhanced security with biometric authentication",
                    "Redesigned user interface for better navigation"
                ),
                improvements = listOf(
                    "Improved app performance and reduced loading times by 30%",
                    "Enhanced offline functionality for core features",
                    "Better accessibility support for screen readers"
                ),
                bugFixes = listOf(
                    "Fixed crash when uploading large images",
                    "Resolved sync issues with cloud storage",
                    "Fixed notification display problems on Android 12+"
                ),
                breakingChanges = listOf(
                    "Minimum Android version requirement increased to 8.0",
                    "Legacy API endpoints have been deprecated"
                ),
                additionalNotes = "This update includes important security improvements. We recommend updating as soon as possible. Some features may require additional permissions on first use."
            )
        }
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_upgrade_notes)
        
        // Get upgrade notes from intent
        val upgradeNotes = intent.getSerializableExtra(EXTRA_UPGRADE_NOTES) as? VersionUpgradeNotes
            ?: createSampleUpgradeNotes()
        
        // Create and setup the fragment
        if (savedInstanceState == null) {
            val fragment = VersionUpgradeNotesFragment.newInstance(upgradeNotes)
            
            // Set up listeners for user actions
            fragment.setOnProceedListener {
                handleProceedWithUpgrade()
            }
            
            fragment.setOnCancelListener {
                handleCancelUpgrade()
            }
            
            // Add fragment to the container
            supportFragmentManager.beginTransaction()
                .replace(R.id.fragment_container, fragment)
                .commit()
        }
        
        // Setup action bar
        supportActionBar?.apply {
            title = getString(R.string.upgrade_notes_screen_title)
            setDisplayHomeAsUpEnabled(true)
        }
    }
    
    override fun onSupportNavigateUp(): Boolean {
        handleCancelUpgrade()
        return true
    }
    
    override fun onBackPressed() {
        handleCancelUpgrade()
    }
    
    /**
     * Handles when user proceeds with the upgrade
     */
    private fun handleProceedWithUpgrade() {
        // In a real app, this would trigger the actual update process
        // For this example, we'll just finish the activity
        setResult(RESULT_OK)
        finish()
    }
    
    /**
     * Handles when user cancels the upgrade
     */
    private fun handleCancelUpgrade() {
        setResult(RESULT_CANCELED)
        finish()
    }
}