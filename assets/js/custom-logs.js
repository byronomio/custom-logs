jQuery(document).ready(function ($) {
    // Cache DOM elements
    const $customViewer = $('#custom-logs-viewer-content');
    const $wpViewer = $('#wp-logs-viewer-content');
    const $customPagination = $('#custom-logs-pagination');
    const $wpPagination = $('#wp-logs-pagination');
    const $customSelect = $('#view_custom_log');
    const $wpSelect = $('#view_wp_log');
    const $customFilter = $('#custom_filter_type');
    const $wpFilter = $('#wp_filter_type');
    const $customPageCount = $('#custom-page-count');
    const $wpPageCount = $('#wp-page-count');

    // Track last update timestamps for each log type
    let lastUpdate = {
        'custom': null,
        'wp': null
    };

    // Auto-refresh interval in milliseconds (e.g., 5000 = 5 seconds)
    const refreshInterval = 5000;

    /**
     * Updates the log viewer content and pagination via AJAX
     * @param {string} logType - 'custom' or 'wp'
     * @param {number} page - The page number to load (default: 1)
     * @param {boolean} force - Whether to force update regardless of last update time
     */
    function updateLogViewer(logType, page = 1, force = false) {
        const $contentContainer = logType === 'custom' ? $customViewer : $wpViewer;
        const $paginationContainer = logType === 'custom' ? $customPagination : $wpPagination;
        const $pageCount = logType === 'custom' ? $customPageCount : $wpPageCount;
        const $select = logType === 'custom' ? $customSelect : $wpSelect;
        const $filter = logType === 'custom' ? $customFilter : $wpFilter;
        const logFile = $select.val();
        const filterType = $filter.val();

        // Get file modification time to check for changes
        $.ajax({
            url: customLogsAjax.ajax_url,
            method: 'POST',
            data: {
                action: 'custom_logs_get_file_mtime',
                nonce: customLogsAjax.nonce,
                log_file: logFile
            },
            success: function (response) {
                if (response.success) {
                    const fileMtime = response.data.mtime;

                    // Only update if file was modified or forced
                    if (force || !lastUpdate[logType] || fileMtime > lastUpdate[logType]) {
                        lastUpdate[logType] = fileMtime;

                        // Add loading state
                        $contentContainer.html('<p class="custom-logs-loading">Loading logs...</p>');

                        // Load the actual content
                        $.ajax({
                            url: customLogsAjax.ajax_url,
                            method: 'POST',
                            data: {
                                action: 'custom_logs_filter_logs',
                                nonce: customLogsAjax.nonce,
                                log_file: logFile,
                                filter_type: filterType,
                                page: page
                            },
                            success: function (response) {
                                if (response.success && response.data) {
                                    $contentContainer.html(response.data.content || '<p class="custom-logs-empty">No logs available.</p>');
                                    // Update pagination buttons and page count
                                    const currentPage = response.data.current_page || 1;
                                    const totalPages = response.data.total_pages || 1;
                                    const $prevBtn = $paginationContainer.find('.custom-logs-prev');
                                    const $nextBtn = $paginationContainer.find('.custom-logs-next');

                                    $prevBtn
                                        .data('page', currentPage > 1 ? currentPage - 1 : 1)
                                        .prop('disabled', currentPage <= 1);
                                    $nextBtn
                                        .data('page', currentPage < totalPages ? currentPage + 1 : totalPages)
                                        .prop('disabled', currentPage >= totalPages);

                                    // Update page count display
                                    if (totalPages > 1) {
                                        $pageCount.text(`Page ${currentPage} of ${totalPages}`);
                                    } else {
                                        $pageCount.text('');
                                    }
                                } else {
                                    $contentContainer.html('<p class="custom-logs-empty">Error loading logs: ' + (response.data || 'Unknown error') + '</p>');
                                    $paginationContainer.find('.custom-logs-prev, .custom-logs-next').prop('disabled', true);
                                    $pageCount.text('');
                                }
                            },
                            error: function (xhr, status, error) {
                                $contentContainer.html('<p class="custom-logs-empty">AJAX request failed: ' + error + '</p>');
                                $paginationContainer.find('.custom-logs-prev, .custom-logs-next').prop('disabled', true);
                                $pageCount.text('');
                            }
                        });
                    }
                }
            },
            error: function (xhr, status, error) {
                console.error('Failed to check file modification time:', error);
            }
        });
    }

    // Event listeners for dropdown changes
    $customSelect.on('change', function () {
        updateLogViewer('custom', 1, true);
    });
    $customFilter.on('change', function () {
        updateLogViewer('custom', 1, true);
    });
    $wpSelect.on('change', function () {
        updateLogViewer('wp', 1, true);
    });
    $wpFilter.on('change', function () {
        updateLogViewer('wp', 1, true);
    });

    // Handle pagination button clicks
    $(document).on('click', '.custom-logs-prev, .custom-logs-next', function (e) {
        e.preventDefault();
        if (!$(this).prop('disabled')) {
            const page = $(this).data('page');
            const $viewer = $(this).closest('.custom-logs-viewer-section');
            const logType = $viewer.find('#custom-logs-viewer-content').length ? 'custom' : 'wp';
            updateLogViewer(logType, page, true);
        }
    });

    // Initial load for both viewers
    updateLogViewer('custom', 1, true);
    updateLogViewer('wp', 1, true);

    // Set up auto-refresh for both viewers
    setInterval(() => {
        updateLogViewer('custom');
    }, refreshInterval);

    setInterval(() => {
        updateLogViewer('wp');
    }, refreshInterval);
});