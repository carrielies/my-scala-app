package controllers

import connectors.CryptoPhotoConnector
import play.api._
import play.api.mvc._
import play.api.data._
import play.api.data.Forms._
import views._

object AuthenticationController extends AuthenticationController {
  override val cryptoPhotoConnector = CryptoPhotoConnector
}

trait AuthenticationController extends Controller {

  val cryptoPhotoConnector : CryptoPhotoConnector
  val loginForm = Form(
    tuple(
      "email" -> text,
      "password" -> text
    )
  )

  /**
    * Login page.
    */
  def login = Action { implicit request =>
    Ok(views.html.login(loginForm))
  }

  /**
    * Logout and clean the session.
    */
  def logout = Action {
    Redirect(routes.AuthenticationController.login).withNewSession.flashing(
      "success" -> "You've been logged out"
    )
  }

  /**
    * Handle login form submission.
    */
  def authenticate = Action { implicit request =>
    loginForm.bindFromRequest.fold(
      formWithErrors => BadRequest(views.html.login(formWithErrors)),
      user => {
        val cryptoSession = cryptoPhotoConnector.session(user._1)

        Ok(views.html.restricted(cryptoSession, user._1))
      }
    )
  }

}