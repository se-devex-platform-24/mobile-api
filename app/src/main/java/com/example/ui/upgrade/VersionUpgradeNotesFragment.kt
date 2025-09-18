package com.example.ui.upgrade

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.R
import com.example.model.VersionUpgradeNotes

/**
 * Fragment to display version upgrade notes to users
 * Provides clear and accessible information about app updates before upgrading
 */
class VersionUpgradeNotesFragment : Fragment() {
    
    private lateinit var versionTitle: TextView
    private lateinit var releaseDate: TextView
    private lateinit var changesRecyclerView: RecyclerView
    private lateinit var additionalNotes: TextView
    private lateinit var proceedButton: Button
    private lateinit var cancelButton: Button
    
    private var upgradeNotes: VersionUpgradeNotes? = null
    private var onProceedListener: (() -> Unit)? = null
    private var onCancelListener: (() -> Unit)? = null
    
    companion object {
        private const val ARG_UPGRADE_NOTES = "upgrade_notes"
        
        /**
         * Creates a new instance of VersionUpgradeNotesFragment with upgrade notes
         */
        fun newInstance(upgradeNotes: VersionUpgradeNotes): VersionUpgradeNotesFragment {
            val fragment = VersionUpgradeNotesFragment()
            val args = Bundle().apply {
                putSerializable(ARG_UPGRADE_NOTES, upgradeNotes)
            }
            fragment.arguments = args
            return fragment
        }
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        arguments?.let { args ->
            upgradeNotes = args.getSerializable(ARG_UPGRADE_NOTES) as? VersionUpgradeNotes
        }
    }
    
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_version_upgrade_notes, container, false)
    }
    
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        initializeViews(view)
        setupUpgradeNotes()
        setupClickListeners()
    }
    
    private fun initializeViews(view: View) {
        versionTitle = view.findViewById(R.id.tv_version_title)
        releaseDate = view.findViewById(R.id.tv_release_date)
        changesRecyclerView = view.findViewById(R.id.rv_changes)
        additionalNotes = view.findViewById(R.id.tv_additional_notes)
        proceedButton = view.findViewById(R.id.btn_proceed_upgrade)
        cancelButton = view.findViewById(R.id.btn_cancel_upgrade)
        
        // Setup RecyclerView
        changesRecyclerView.layoutManager = LinearLayoutManager(requireContext())
    }
    
    private fun setupUpgradeNotes() {
        upgradeNotes?.let { notes ->
            // Set version title
            versionTitle.text = getString(R.string.version_upgrade_title, notes.version)
            
            // Set release date
            releaseDate.text = getString(R.string.release_date_format, notes.releaseDate)
            
            // Setup changes list
            val allChanges = mutableListOf<ChangeItem>()
            
            // Add key changes
            if (notes.keyChanges.isNotEmpty()) {
                allChanges.add(ChangeItem.Header(getString(R.string.key_changes_header)))
                notes.keyChanges.forEach { change ->
                    allChanges.add(ChangeItem.Change(change, ChangeType.KEY_CHANGE))
                }
            }
            
            // Add improvements
            if (notes.improvements.isNotEmpty()) {
                allChanges.add(ChangeItem.Header(getString(R.string.improvements_header)))
                notes.improvements.forEach { improvement ->
                    allChanges.add(ChangeItem.Change(improvement, ChangeType.IMPROVEMENT))
                }
            }
            
            // Add bug fixes
            if (notes.bugFixes.isNotEmpty()) {
                allChanges.add(ChangeItem.Header(getString(R.string.bug_fixes_header)))
                notes.bugFixes.forEach { fix ->
                    allChanges.add(ChangeItem.Change(fix, ChangeType.BUG_FIX))
                }
            }
            
            // Add breaking changes with warning
            if (notes.breakingChanges.isNotEmpty()) {
                allChanges.add(ChangeItem.Header(getString(R.string.breaking_changes_header)))
                notes.breakingChanges.forEach { change ->
                    allChanges.add(ChangeItem.Change(change, ChangeType.BREAKING_CHANGE))
                }
            }
            
            changesRecyclerView.adapter = UpgradeNotesAdapter(allChanges)
            
            // Set additional notes
            if (notes.additionalNotes.isNotEmpty()) {
                additionalNotes.text = notes.additionalNotes
                additionalNotes.visibility = View.VISIBLE
            } else {
                additionalNotes.visibility = View.GONE
            }
            
            // Show warning if there are breaking changes
            if (notes.hasBreakingChanges()) {
                proceedButton.text = getString(R.string.proceed_with_caution)
            }
        }
    }
    
    private fun setupClickListeners() {
        proceedButton.setOnClickListener {
            onProceedListener?.invoke()
        }
        
        cancelButton.setOnClickListener {
            onCancelListener?.invoke()
        }
    }
    
    /**
     * Sets the listener for when user proceeds with upgrade
     */
    fun setOnProceedListener(listener: () -> Unit) {
        onProceedListener = listener
    }
    
    /**
     * Sets the listener for when user cancels upgrade
     */
    fun setOnCancelListener(listener: () -> Unit) {
        onCancelListener = listener
    }
    
    // Data classes for RecyclerView items
    sealed class ChangeItem {
        data class Header(val title: String) : ChangeItem()
        data class Change(val description: String, val type: ChangeType) : ChangeItem()
    }
    
    enum class ChangeType {
        KEY_CHANGE,
        IMPROVEMENT,
        BUG_FIX,
        BREAKING_CHANGE
    }
    
    // Simple adapter for displaying changes
    private class UpgradeNotesAdapter(
        private val items: List<ChangeItem>
    ) : RecyclerView.Adapter<RecyclerView.ViewHolder>() {
        
        companion object {
            private const val TYPE_HEADER = 0
            private const val TYPE_CHANGE = 1
        }
        
        override fun getItemViewType(position: Int): Int {
            return when (items[position]) {
                is ChangeItem.Header -> TYPE_HEADER
                is ChangeItem.Change -> TYPE_CHANGE
            }
        }
        
        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
            val inflater = LayoutInflater.from(parent.context)
            return when (viewType) {
                TYPE_HEADER -> {
                    val view = inflater.inflate(R.layout.item_upgrade_notes_header, parent, false)
                    HeaderViewHolder(view)
                }
                TYPE_CHANGE -> {
                    val view = inflater.inflate(R.layout.item_upgrade_notes_change, parent, false)
                    ChangeViewHolder(view)
                }
                else -> throw IllegalArgumentException("Unknown view type: $viewType")
            }
        }
        
        override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
            when (val item = items[position]) {
                is ChangeItem.Header -> {
                    (holder as HeaderViewHolder).bind(item)
                }
                is ChangeItem.Change -> {
                    (holder as ChangeViewHolder).bind(item)
                }
            }
        }
        
        override fun getItemCount(): Int = items.size
        
        private class HeaderViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
            private val headerText: TextView = itemView.findViewById(R.id.tv_header)
            
            fun bind(header: ChangeItem.Header) {
                headerText.text = header.title
            }
        }
        
        private class ChangeViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
            private val changeText: TextView = itemView.findViewById(R.id.tv_change)
            private val changeIcon: View = itemView.findViewById(R.id.iv_change_icon)
            
            fun bind(change: ChangeItem.Change) {
                changeText.text = change.description
                
                // Set appropriate icon/color based on change type
                when (change.type) {
                    ChangeType.KEY_CHANGE -> {
                        changeIcon.setBackgroundResource(R.drawable.ic_star)
                    }
                    ChangeType.IMPROVEMENT -> {
                        changeIcon.setBackgroundResource(R.drawable.ic_improvement)
                    }
                    ChangeType.BUG_FIX -> {
                        changeIcon.setBackgroundResource(R.drawable.ic_bug_fix)
                    }
                    ChangeType.BREAKING_CHANGE -> {
                        changeIcon.setBackgroundResource(R.drawable.ic_warning)
                    }
                }
            }
        }
    }
}