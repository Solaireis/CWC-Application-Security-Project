function submitValues(timing, orderID, payerID) {
    console.log("Setting Values...");
    document.getElementById("checkoutTiming").value = timing;            //Time purchase was last edited
    document.getElementById("checkoutOrderID").value = orderID;          //Order ID
    document.getElementById("checkoutPayerID").value = payerID;          //PayPal-Assigned Payer ID
    document.getElementById("checkoutComplete").value = "True";
    document.getElementById("paypal-complete").submit();
}

paypal.Buttons({
        // Sets up the transaction when a payment button is clicked
        createOrder: function(data, actions) {
          return actions.order.create({
            purchase_units: [{
              amount: {
                // Can reference variables or functions. Example: `value: document.getElementById('...').value`
                value: document.getElementById("hidden-subtotal").innerText
              }
            }]
          });
        },

        // Finalize the transaction after payer approval
        onApprove: function(data, actions) {
          return actions.order.capture().then(function(orderData) {
            /* For dev/demo purposes:
            console.log('Capture result');
            console.log(orderData);
            var transaction = orderData.purchase_units[0].payments.captures[0];
            console.log(transaction);     //Dictionary of transaction info      */

            submitValues(orderData.update_time, orderData.id, orderData.payer.payer_id);

            /*
            //Debug
            console.log("Payment Complete.");

            console.log(orderData.update_time);
            console.log(orderData.id);
            console.log(orderData.payer.payer_id);*/

          });
        },

        style: {//Using default Values
          layout:  'vertical',
          color:   'gold',
          shape:   'rect',
          label:   'pay'
        },

        onError: function (err) {
          var paypal_error = new bootstrap.Modal(document.getElementById('paypalErrorModal'));
          paypal_error.show();
        },

      }).render('#paypal-button-container');



/*
Checkout Options:
https://developer.paypal.com/docs/checkout/

Payment Notifications:
https://developer.paypal.com/developer/notifications

Javascript Reference SDK:
https://developer.paypal.com/sdk/js/reference

PayPal Orders API:
https://developer.paypal.com/api/orders/v2

Sandbox Account Credentials:
https://developer.paypal.com/developer/accounts

CourseFinity Web App Configuration
https://developer.paypal.com/developer/applications/edit/SB:QVVUaDgzSk16OG1MTkdOenB6SlJKU2JTTFVBRXA3b2UxaWVHR3FZQ21WWHBxNDI3RGVTVkVsa0huYzB0dDcwYjhnSGxXZzR5RVRuTEx1MXM=?appname=CourseFinity%20Flask%20Web%20App

Pretty Print JSON
https://jsonformatter.org/json-pretty-print


Email:
sb-gzjpl11768707@personal.example.com

Password:
c&V#>L_8
*/

