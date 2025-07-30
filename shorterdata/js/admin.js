document.addEventListener('DOMContentLoaded', function () {
    const deleteButtons = document.querySelectorAll('.delete-button');

    deleteButtons.forEach(button => {
        button.addEventListener('click', function (event) {
            const message = button.getAttribute('data-confirm');
            if (message && !confirm(message)) {
                // If the user clicks "Cancel", prevent the form submission.
                event.preventDefault();
            }
        });
    });
});