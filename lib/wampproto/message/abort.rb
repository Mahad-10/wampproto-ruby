# frozen_string_literal: true

module Wampproto
  module Message
    # interface for abort fields
    module IAbortFields
      def details
        raise NotImplementedError
      end

      def reason
        raise NotImplementedError
      end

      def args
        raise NotImplementedError
      end

      def kwargs
        raise NotImplementedError
      end
    end

    # abort fields
    class AbortFields
      include IAbortFields
      attr_reader :details, :reason, :args, :kwargs

      def initialize(details, reason, args: nil, kwargs: nil)
        super()
        @details = details
        @reason = reason
        @args = args
        @kwargs = kwargs
      end
    end

    # abort message
    class Abort < Base
      include IAbortFields
      attr_reader :details, :reason, :args, :kwargs

      TEXT = "ABORT"
      VALIDATION_SPEC = Message::ValidationSpec.new(
        3,
        5,
        TEXT,
        {
          1 => Message::Util.method(:validate_details),
          2 => Message::Util.method(:validate_reason),
          3 => Message::Util.method(:validate_args),
          4 => Message::Util.method(:validate_kwargs)
        }
      )

      def initialize(details, reason, args: nil, kwargs: nil)
        super()
        @details = details
        @reason = reason
        @args = args
        @kwargs = kwargs
      end

      def self.with_fields(fields)
        new(fields.details, fields.reason, args: fields.args, kwargs: fields.kwargs)
      end

      def marshal
        @marshal = [Type::ABORT, @details, @reason]

        @marshal << @args unless @args.nil?
        unless @kwargs.nil?
          @marshal << [] if @args.nil?
          @marshal << @kwargs if @kwargs.any?
        end
        @marshal
      end

      def self.parse(wamp_message)
        fields = Util.validate_message(wamp_message, Type::ABORT, VALIDATION_SPEC)
        Abort.with_fields(fields)
      end
    end
  end
end
