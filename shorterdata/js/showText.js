document.addEventListener('DOMContentLoaded', function () {
    const copyButton = document.getElementById('copy-button');
    const textArea = document.getElementById('text-dump-content');

    if (copyButton && textArea) {
        copyButton.addEventListener('click', function () {
            navigator.clipboard.writeText(textArea.value).then(function () {
                const originalText = copyButton.innerText;
                copyButton.innerText = 'Copied!';
                setTimeout(function () {
                    copyButton.innerText = originalText;
                }, 2000);
            }).catch(err => console.error('Failed to copy text: ', err));
        });
    }
});
