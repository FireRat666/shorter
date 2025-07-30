document.addEventListener('DOMContentLoaded', function () {
    // Find all forms that contain a submit button with a data-confirm attribute.
    document.querySelectorAll('form').forEach(form => {
        // Find the specific submit button within this form.
        const submitButton = form.querySelector('input[type="submit"][data-confirm]');

        // If this form doesn't have a confirmation button, skip it.
        if (!submitButton) {
            return;
        }

        // Listen for the 'submit' event on the form itself. This is more reliable
        // than listening for a 'click' on the button.
        form.addEventListener('submit', function (event) {
            const message = submitButton.getAttribute('data-confirm');

            // If the message exists and the user clicks "Cancel" in the confirmation dialog...
            if (message && !window.confirm(message)) {
                // ...then prevent the form from being submitted.
                event.preventDefault();
            }
            // Otherwise, if the user clicks "OK", the event is not prevented,
            // and the form will submit as normal.
        });
    });

    // Handle the "select all" checkbox for bulk link deletion.
    const selectAllCheckbox = document.getElementById('select-all-links');
    const linkCheckboxes = document.querySelectorAll('.link-checkbox');

    if (selectAllCheckbox && linkCheckboxes.length > 0) {
        selectAllCheckbox.addEventListener('change', function() {
            linkCheckboxes.forEach(checkbox => {
                checkbox.checked = selectAllCheckbox.checked;
            });
        });
    }
});