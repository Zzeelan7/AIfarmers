// ===== Modal Controls =====
function openModal() {
  document.getElementById('loginModal').style.display = 'block';
}

function closeModal() {
  document.getElementById('loginModal').style.display = 'none';
}

// Close modal when clicking outside the box
window.onclick = function (event) {
  const modal = document.getElementById('loginModal');
  if (event.target === modal) {
    modal.style.display = 'none';
  }
};

// ===== Optional: Smooth Scroll for Internal Links =====
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', function (e) {
    e.preventDefault();
    const target = document.querySelector(this.getAttribute('href'));
    if (target) {
      target.scrollIntoView({ behavior: 'smooth' });
    }
  });
});
