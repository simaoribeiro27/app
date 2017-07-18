angular.module('viagemController', [])

	// inject  service factory into our controller
	.controller('mainController', ['$scope','$http','Viagens', function($scope, $http, Viageens) {
		$scope.formData = {};
		$scope.loading = true;

		// GET =====================================================================
		// get all and show them
		// use the service to get all 
		Todos.get()
			.success(function(data) {
				$scope.viagens = data;
				$scope.loading = false;
			});

		// CREATE ==================================================================
		// when submitting the add form, send the text to the node API
		$scope.createViagem = function() {
			// validate the formData to make sure that something is there
			// if form is empty, nothing will happen
			if ($scope.formData.text != undefined) {
				$scope.loading = true;

				// call the create function from our service (returns a promise object)
				Viagens.create($scope.formData)

					// if successful creation, call our get function to get all the new todos
					.success(function(data) {
						$scope.loading = false;
						$scope.formData = {}; // clear the form so our user is ready to enter another
						$scope.viagens = data; // assign our new list of todos
					});
			}
		};

		// DELETE ==================================================================
		// delete a todo after checking it
		$scope.deleteViagem = function(id) {
			$scope.loading = true;

			Viagens.delete(id)
				// if successful creation, call our get function to get all the new todos
				.success(function(data) {
					$scope.loading = false;
					$scope.viagens = data; // assign our new list of todos
				});
		};
	}]);