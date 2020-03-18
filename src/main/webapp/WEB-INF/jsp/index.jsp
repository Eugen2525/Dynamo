<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html;charset=UTF-8">
<title>Document</title>
<!--Import Google Icon Font-->
<link href="https://fonts.googleapis.com/icon?family=Material+Icons"
	rel="stylesheet">
<script
	src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>
<!--Import materialize.css-->
<link rel="stylesheet"
	href="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/css/materialize.min.css">
<!--Let browser know website is optimized for mobile-->
<meta name="viewport" content="width=device-width, initial-scale=1.0" />

<!-- Custom css file -->
<link rel="stylesheet" href="/css/style.css">
<!-- Compiled and minified JavaScript -->
<script
	src="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/js/materialize.min.js"></script>

<!-- Font awesome CSS files -->
<link rel="stylesheet"
	href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.11.2/css/all.css">
<!-- Custom JS -->
<script type="text/javascript" src="/js/app.js"></script>
</head>
<body>
	<header>
	<div class="container-fluid">
		<nav>
		<div class="nav-wrapper">
			<a href="/" class="brand-logo"><i class="material-icons">filter_drama</i>ZixCloudFoundary</a>
			<ul id="nav" class="right hide-on-med-and-down">
				<li><a href="/">Home</a></li>
				<li><a href="/offers">Offers</a></li>
				<li><a href="/services">Services</a></li>
				<li><a class="modal-trigger" href="#modal12">Login</a></li>
			</ul>
		</div>
		</nav>
	</div>
	</header>

	<!-- Here starts main section -->
	<main>
	<div class="carousel carousel-slider" data-indicators="true">

		<div class="carousel-fixed-item center">
			<a class="btn waves-effect pink grey-text darken-text-2"
				onclick="M.toast({html:'Taking you to login page.', classes:'rounded'})">Get
				Started</a>
		</div>

		<a href="" class="carousel-item"><img src="/images/carousel/1.jpg"
			alt="car-1"></a> <a href="" class="carousel-item"><img
			src="/images/carousel/2.jpg" alt="car-2"></a> <a href=""
			class="carousel-item"><img src="/images/carousel/3.jpg"
			alt="car-3"></a> <a href="" class="carousel-item"><img
			src="/images/carousel/4.jpg" alt="car-4"></a>

		<!--  <nav>
                  <div class="nav-wrapper">
                       <a href="/" class="brand-logo"><i class="material-icons">filter_drama</i> ZixCloudFoundary</a>
                       <ul id="nav" class="right hide-on-med-and-down">
                             <li><a href="/home">Home</a></li>
                             <li><a href="/offers">Offers</a></li>
                             <li><a href="/services">Services</a></li>
                             <li><a class="waves-effect waves-light btn modal-trigger" href="#modal12">Login</a></li>
                       </ul>
                 </div>
                 </nav>  -->
	</div>

	<!-- Modal-Login/register for  -->
	<div id="modal12" class="modal">
		<div class="modal-content">

			<ul class="tabs">
				<li class="tab col s6"><a href="#login_tab">Login</a></li>
				<li class="tab col s6"><a href="#register_form">Register</a></li>
			</ul>


			<form action="login" method="post">
				<div class="Login" id="login_tab">
					<div class="container row">
						<div class="col s12">
							<div class="row">
								<h4 class="text-darken-4 center">Login</h4>
								<div class="input-field col s12">
									<i class="material-icons prefix">account_circle</i> <input
										type="text" name="userid" class="validate" id="userid">
									<label for="userid">User ID</label>
								</div>
							</div>
							<div class="row">
								<div class="input-field col s12">
									<i class="fas fa-key prefix"></i> <input type="password"
										name="password" class="validate" id="password"> <label
										for="password">Password</label>
								</div>
							</div>
						</div>
					</div>
					<button class="waves-effect waves-green btn-flat right"
						type="submit">Login</button>
					<a class="modal-close waves-effect waves-green btn-flat right">Close</a>
				</div>
			</form>


			<!-- Register model form  -->
			<form action="register" method="post">
				<div class="register" id="register_form">
					<div class="row">
						<div class="col s12">
							<div class="row">
								<div class="input-field col s6">
									<i class="fas fa-user prefix"></i> <input type="text"
										name="first_name" id="first_name" class="validate"> <label
										for="first_name">First Name</label>
								</div>
								<div class="input-field col s6">
									<i class="fas fa-user prefix"></i> <input type="text"
										name="last_name" id="last_name" class="validate"> <label
										for="last_name">Last Name</label>
								</div>
							</div>
							<div class="row">
								<div class="input-field col s6">
									<i class="material-icons prefix">local_phone</i> <input
										type="text" name="number" class="validate" id="phone_num">
									<label for="phone_num">Phone</label>
								</div>

								<div class="input-field col s6">
									<i class="material-icons prefix">mail</i> <input type="text"
										name="email" class="validate" id="email"> <label
										for="email">Email</label>
								</div>
							</div>

							<div class="row">
								<div class="input-field col s6">
									<i class="fas fa-key prefix"></i> <input type="password"
										name="password" class="validate" id="pass"> <label
										for="pass">Password</label>
								</div>
								<div class="input-field col s6">
									<input type="text" name="city" class="validate" id="city">
									<label for="city">City</label>
								</div>
							</div>
							<div class="row">
								<div class="input-field col s6">
									<i class="fas fa-building prefix"></i> <input type="text"
										name="state" class="validate" id="state"> <label
										for="state">State</label>
								</div>
								<div class="input-field col s6">
									<i class="fas fa-flag prefix"></i> <input type="text"
										name="country" class="validate" id="country"> <label
										for="country">Country</label>
								</div>
							</div>
							<button class="waves-effect waves-green btn-flat right"
								type="submit">Register</button>
							<a class="modal-close waves-effect waves-green btn-flat right">Close</a>
						</div>
					</div>
				</div>
			</form>
		</div>
	</div>


	<div class="section white container">
		<div class="row" id="slider">
			<div class="col s12 m4">

				<!--First card -->
				<div class="card z-depth-5">
					<div class="card-image waves-block waves-effect waves-light">
						<img src="/images/card/furnishing.jpg" class="activator" alt="">
					</div>
					<div class="card-content">
						<span class="card-title activator grey-text text-darken-5"><i
							class="material-icons right">more_vert</i>
							<p>
								<a class="waves-effect waves-light btn modal-trigger"
									href="#model1">Open model</a>
							</p> </span>
					</div>
					<div class="card-reveal">
						<span class="card-title grey-text text-darken-4"> Card
							Title<i class="material-icons right">close</i>
							<p>Lorem ipsum dolor sit amet, consectetur adipisicing elit.
								Similique, odio.</p>
						</span>
					</div>
				</div>
			</div>

			<div class="col s12 m4">
				<!-- Second card -->
				<div class="card z-depth-5">
					<div class="card-image waves-block waves-effect waves-light">
						<img src="/images/card/grey-steel-flame.jpg" class="activator"
							alt="">
					</div>
					<div class="card-content">
						<span class="card-title activator grey-text text-darken-5"><i
							class="material-icons right">more_vert</i>
							<p>
								<a class="waves-effect waves-light btn modal-trigger"
									href="#model2">Open model</a>
							</p> </span>
					</div>
					<div class="card-reveal">
						<span class="card-title grey-text text-darken-4"> Card
							Title<i class="material-icons right">close</i>
							<p>Lorem ipsum dolor sit amet, consectetur adipisicing elit.
								Similique, odio.</p>
						</span>
					</div>
				</div>

			</div>
			<div class="col s12 m4">
				<!-- Third card -->
				<div class="card z-depth-5">
					<div class="card-image waves-block waves-effect waves-light">
						<img src="/images/card/electrician.jpg" class="activator" alt="">
					</div>
					<div class="card-content">
						<span class="card-title activator grey-text text-darken-5"><i
							class="material-icons right">more_vert</i>
							<p>
								<a class="waves-effect waves-light btn modal-trigger"
									href="#model3">Open model</a>
							</p> </span>
					</div>
					<div class="card-reveal">
						<span class="card-title grey-text text-darken-4"> Card
							Title<i class="material-icons right">close</i>
							<p>Lorem ipsum dolor sit amet, consectetur adipisicing elit.
								Similique, odio.</p>
						</span>
					</div>
				</div>
			</div>
		</div>
		<!-- Second row -->
		<div class="row" id="slider">
			<div class="col s12 m4">

				<!--First card -->
				<div class="card z-depth-5">
					<div class="card-image waves-block waves-effect waves-light">
						<img src="/images/card/furnishing.jpg" class="activator" alt="">
					</div>
					<div class="card-content">
						<span class="card-title activator grey-text text-darken-5"><i
							class="material-icons right">more_vert</i>
							<p>
								<a class="waves-effect waves-light btn modal-trigger"
									href="#model4">Explore</a>
							</p> </span>
					</div>
					<div class="card-reveal">
						<span class="card-title grey-text text-darken-4"> Card
							Title<i class="material-icons right">close</i>
							<p>Lorem ipsum dolor sit amet, consectetur adipisicing elit.
								Similique, odio.</p>
						</span>
					</div>
				</div>
			</div>

			<div class="col s12 m4">
				<!-- Second card -->
				<div class="card z-depth-5">
					<div class="card-image waves-block waves-effect waves-light">
						<img src="/images/card/grey-steel-flame.jpg" class="activator"
							alt="">
					</div>
					<div class="card-content">
						<span class="card-title activator grey-text text-darken-5"><i
							class="material-icons right">more_vert</i>
							<p>
								<a class="waves-effect waves-light btn modal-trigger"
									href="#model5">View All</a>
							</p> </span>
					</div>
					<div class="card-reveal">
						<span class="card-title grey-text text-darken-4"> Card
							Title<i class="material-icons right">close</i>
							<p>Lorem ipsum dolor sit amet, consectetur adipisicing elit.
								Similique, odio.</p>
						</span>
					</div>
				</div>

			</div>
			<div class="col s12 m4">
				<!-- Third card -->
				<div class="card z-depth-5">
					<div class="card-image waves-block waves-effect waves-light">
						<img src="/images/card/electrician.jpg" class="activator" alt="">
					</div>
					<div class="card-content">
						<span class="card-title activator grey-text text-darken-5"><i
							class="material-icons right">more_vert</i>
							<p>
								<a class="waves-effect waves-light btn modal-trigger"
									href="#model6">Open model</a>
							</p> </span>
					</div>
					<div class="card-reveal">
						<span class="card-title grey-text text-darken-4"> Card
							Title<i class="material-icons right">close</i>
							<p>Lorem ipsum dolor sit amet, consectetur adipisicing elit.
								Similique, odio.</p>
						</span>
					</div>
				</div>
			</div>
		</div>
	</div>
	<!-- Parallax after the cards --> <!-- <a href="https://www.freepik.com/free-photos-vectors/background">Background vector created by freepik - www.freepik.com</a> -->
	<div class="parallax-container">
		<div class="parallax">
			<img src="/images/parallax/shape.jpg" alt="woment face glittered">
		</div>
	</div>

	<!-- Model Container's -->
	<div id="model1" class="modal">
		<div class="modal-content">
			<h4>Lorem ipsum dolor sit amet.</h4>
			<p>Lorem ipsum dolor sit amet, consectetur adipisicing elit.
				Recusandae, dolorem et eos. Consequuntur eos perspiciatis mollitia
				fuga fugiat accusamus assumenda?</p>
		</div>
		<div class="modal-footer">
			<a href="#" class="modal-close waves-effect waves-green btn-flat">Agree</a>
		</div>
	</div>

	<div id="model2" class="modal">
		<div class="modal-content">
			<h4>Lorem ipsum dolor sit amet.</h4>
			<p>Lorem ipsum dolor sit amet, consectetur adipisicing elit.
				Recusandae, dolorem et eos. Consequuntur eos perspiciatis mollitia
				fuga fugiat accusamus assumenda?</p>
		</div>
		<div class="modal-footer">
			<a href="#" class="modal-close waves-effect waves-green btn-flat">Agree</a>
		</div>
	</div>

	<div id="model3" class="modal">
		<div class="modal-content">
			<h4>Lorem ipsum dolor sit amet.</h4>
			<p>Lorem ipsum dolor sit amet, consectetur adipisicing elit.
				Recusandae, dolorem et eos. Consequuntur eos perspiciatis mollitia
				fuga fugiat accusamus assumenda?</p>
		</div>
		<div class="modal-footer">
			<a href="#" class="modal-close waves-effect waves-green btn-flat">Agree</a>
		</div>
	</div>

	<div id="model4" class="modal">
		<div class="modal-content">
			<h4>Lorem ipsum dolor sit amet.</h4>
			<p>Lorem ipsum dolor sit amet, consectetur adipisicing elit.
				Recusandae, dolorem et eos. Consequuntur eos perspiciatis mollitia
				fuga fugiat accusamus assumenda?</p>
		</div>
		<div class="modal-footer">
			<a href="#" class="modal-close waves-effect waves-green btn-flat">Agree</a>
		</div>
	</div>

	<div id="model5" class="modal">
		<div class="modal-content">
			<h4>Lorem ipsum dolor sit amet.</h4>
			<p>Lorem ipsum dolor sit amet, consectetur adipisicing elit.
				Recusandae, dolorem et eos. Consequuntur eos perspiciatis mollitia
				fuga fugiat accusamus assumenda?</p>
		</div>
		<div class="modal-footer">
			<a href="#" class="modal-close waves-effect waves-green btn-flat">Agree</a>
		</div>
	</div>

	<div id="model6" class="modal">
		<div class="modal-content">
			<h4>Lorem ipsum dolor sit amet.</h4>
			<p>Lorem ipsum dolor sit amet, consectetur adipisicing elit.
				Recusandae, dolorem et eos. Consequuntur eos perspiciatis mollitia
				fuga fugiat accusamus assumenda?</p>
		</div>
		<div class="modal-footer">
			<a href="#" class="modal-close waves-effect waves-green btn-flat">Agree</a>
		</div>
	</div>
	<div class="section white">
		<div class="row container">
			<div class="col l4 s12">
				<h5 class="truncate">Who we're.</h5>
				<p class="grey-text text-darken-4">Lorem ipsum dolor sit amet,
					consectetur adipisicing elit. Repellat odio amet quae repellendus
					earum necessitatibus voluptatem, fugiat, aspernatur id totam!</p>
				<a href="" class="waves-effect white waves-white black-text btn">Support
					Us</a>
			</div>
			<div class="col l4 s12">
				<h5 class="truncate">What we do.</h5>
				<p class="grey-text text-darken-4">Lorem ipsum dolor sit amet,
					consectetur adipisicing elit. Repellat odio amet quae repellendus
					earum necessitatibus voluptatem, fugiat, aspernatur id totam!</p>
				<a href="" class="waves-effect white waves-white black-text btn">Contact
					Us</a>
			</div>

			<div class="col l4 s12">
				<h5 class="truncate">Connect Us</h5>
				<a href="mailto=amitmishra1800@gmail.com"
					class="waves-effect white waves-white black-text btn">Email us
					<i class="fas fa-envelope"></i>
				</a>
			</div>
		</div>
	</div>
	</main>


	<!-- All opened model data and contents -->


	<!-- Footer starts from here -->
	<footer class="page-footer">
	<div class="container">
		<div class="row">
			<div class="col l6 s12">
				<h5 class="white-text">Next Generation Cloud Computing.</h5>
				<p class="grey-text text-lighten-4">We're open for you 24x7.</p>
			</div>
			<div class="col l4 offset-l2 s12">
				<h5 class="white-text">All rights are reserved.</h5>
				<ul>
					<li><a class="grey-text text-lighten-3" href="#!">Terms Of
							Service</a></li>
					<li><a class="grey-text text-lighten-3" href="#!">Privacy
							Policy</a></li>
					<li><a class="grey-text text-lighten-3" href="#!">Legal</a></li>
					<li><a class="grey-text text-lighten-3" href="#!">Cookie
							Policy</a></li>
				</ul>
			</div>
		</div>
	</div>
	<div class="footer-copyright">
		<div class="container">
			© 2020 Zix Cloud Corporation. All rights Reserved. <a
				class="grey-text text-lighten-4 right" href="#!">Service List</a>
		</div>
	</div>
	</footer>
</body>
</html>