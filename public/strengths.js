
    const strengthButtons =
      document.querySelectorAll(".strength-button");


    strengthButtons.forEach(function(button) {

      button.addEventListener("click", function() {

        const targetId =
          button.getAttribute("aria-controls");

        const content =
          document.getElementById(targetId);

        const isOpen =
          button.getAttribute("aria-expanded") === "true";


        button.setAttribute(
          "aria-expanded",
          String(!isOpen)
        );


        content.classList.toggle(
          "open",
          !isOpen
        );

      });

    });

