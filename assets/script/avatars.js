document.addEventListener("DOMContentLoaded", function () {
    const urlParams = new URLSearchParams(window.location.search);
    const page = urlParams.get('page') || 'settings/profile';
    const tab = page.split('/')[1] || 'profile';
    showTab(tab);

    // Add event listener to the submit button
    const submitButton = document.getElementById('submit-avatar');
    if (submitButton) {
        submitButton.addEventListener('click', submitAvatar);
    }
});

function showTab(tabName) {
    const tabs = document.getElementsByClassName('tab-content');
    for (let i = 0; i < tabs.length; i++) {
        tabs[i].style.display = "none";
    }
    const tabButtons = document.getElementsByClassName('tab-button');
    for (let i = 0; i < tabButtons.length; i++) {
        tabButtons[i].classList.remove('active');
    }
    document.getElementById(tabName).style.display = "block";
    for (let i = 0; i < tabButtons.length; i++) {
        if (tabButtons[i].getAttribute('href').includes(tabName)) {
            tabButtons[i].classList.add('active');
        }
    }
}

function selectAvatar(avatar) {
    const avatars = document.querySelectorAll('.avatar');
    avatars.forEach(function (avatarElement) {
        avatarElement.classList.remove('selected');
    });
    const selectedAvatar = document.querySelector(`img[src='../assets/img/users/${avatar}']`);
    if (selectedAvatar) {
        selectedAvatar.classList.add('selected');
        document.getElementById('selected-avatar').value = avatar;
    }
}

function submitAvatar() {
    const selectedAvatar = document.getElementById('selected-avatar').value;
    if (selectedAvatar) {
        fetch('/private/change_avatars.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `selected-avatar=${encodeURIComponent(selectedAvatar)}`
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => { throw err; });
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                updateAvatarDisplay(data.avatar);
                showMessage('Avatar updated successfully', 'success');
            } else {
                throw new Error(data.message || 'Failed to update avatar');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showMessage(error.message || 'An error occurred while updating the avatar', 'error');
        });
    } else {
        showMessage('Please select an avatar first', 'error');
    }
}

function updateAvatarDisplay(avatar) {
    const userAvatarImgs = document.querySelectorAll('.user-avatar');
    userAvatarImgs.forEach(img => {
        img.src = `../assets/img/users/${avatar}`;
    });
}

function showMessage(message, type = 'info') {
    const messageElement = document.getElementById('message');
    if (!messageElement) {
        const newMessageElement = document.createElement('div');
        newMessageElement.id = 'message';
        document.body.appendChild(newMessageElement);
    }
    const messageDiv = document.getElementById('message');
    messageDiv.textContent = message;
    messageDiv.className = type;
    messageDiv.style.display = 'block';
    setTimeout(() => {
        messageDiv.style.display = 'none';
    }, 5000);
}